// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <txreconciliation.h>

namespace {

/** Default coefficient used to estimate set difference for tx reconciliation. */
constexpr double DEFAULT_RECON_Q = 0.02;
/** Static component of the salt used to compute short txids for transaction reconciliation. */
const std::string RECON_STATIC_SALT = "Tx Relay Salting";

/**
 * A salt is specified by BIP-330 is constructed from contributions from both peers, and is later
 * used to construct transaction short IDs to be used for efficient transaction reconciliations.
 */
uint256 ComputeSalt(uint64_t local_salt, uint64_t remote_salt)
{
    uint64_t salt1 = local_salt, salt2 = remote_salt;
    if (salt1 > salt2) std::swap(salt1, salt2);
    static const auto RECON_SALT_HASHER = TaggedHash(RECON_STATIC_SALT);
    return (CHashWriter(RECON_SALT_HASHER) << salt1 << salt2).GetSHA256();
}

/**
 * This struct is used to keep track of the reconciliations with a given peer,
 * and also short transaction IDs for the next reconciliation round.
 * Transaction reconciliation means an efficient synchronization of the known
 * transactions between a pair of peers.
 * One reconciliation round consists of a sequence of messages. The sequence is
 * asymmetrical, there is always a requestor and a responder. At the end of the
 * sequence, nodes are supposed to exchange transactions, so that both of them
 * have all relevant transactions. For more protocol details, refer to BIP-0330.
 */
struct ReconciliationState {
    /** Whether this peer will send reconciliation requests. */
    bool m_requestor;

    /** Whether this peer will respond to reconciliation requests. */
    bool m_responder;

    /**
     * Since reconciliation-only approach makes transaction relay
     * significantly slower, we also announce some of the transactions
     * (currently, transactions received from inbound links)
     * to some of the peers:
     * - all pre-reconciliation peers supporting transaction relay;
     * - a limited number of outbound reconciling peers *for which this flag is enabled*.
     * We enable this flag based on whether we have a
     * sufficient number of outbound transaction relay peers.
     * This flooding makes transaction relay across the network faster
     * without introducing high the bandwidth overhead.
     * Transactions announced via flooding should not be added to
     * the reconciliation set.
     */
    bool m_flood_to;

    /**
     * Reconciliation involves computing and transmitting sketches,
     * which is a bandwidth-efficient representation of transaction IDs.
     * Since computing sketches over full txID is too CPU-expensive,
     * they will be computed over shortened IDs instead.
     * These short IDs will be salted so that they are not the same
     * across all pairs of peers, because otherwise it would enable network-wide
     * collisions which may (intentionally or not) halt relay of certain transactions.
     * Both of the peers contribute to the salt.
     */
    const uint64_t m_k0, m_k1;

    /**
     * Computing a set reconciliation sketch involves estimating the difference
     * between sets of transactions on two sides of the connection. More specifically,
     * a sketch capacity is computed as
     * |set_size - local_set_size| + q * (set_size + local_set_size) + c,
     * where c is a small constant, and q is a node+connection-specific coefficient.
     * This coefficient is recomputed by every node based on its previous reconciliations,
     * to better predict future set size differences.
     */
    double m_local_q;

    ReconciliationState(bool requestor, bool responder, bool flood_to, uint64_t k0, uint64_t k1) :
        m_requestor(requestor), m_responder(responder), m_flood_to(flood_to),
        m_k0(k0), m_k1(k1), m_local_q(DEFAULT_RECON_Q) {}
};

} // namespace

/** Actual implementation for TxReconciliationTracker's data structure. */
class TxReconciliationTracker::Impl {

    mutable Mutex m_mutex;
    /**
     * Salt used to compute short IDs during transaction reconciliation.
     * Salt is generated randomly per-connection to prevent linking of
     * connections belonging to the same physical node.
     * Also, salts should be different per-connection to prevent halting
     * of relay of particular transactions due to collisions in short IDs.
     */
    std::unordered_map<NodeId, uint64_t> m_local_salts GUARDED_BY(m_mutex);

    /**
     * Used to keep track of ongoing reconciliations per peer.
     */
    std::unordered_map<NodeId, ReconciliationState> m_states GUARDED_BY(m_mutex);

    /**
     * Reconciliation should happen with peers in the same order, because the efficiency gain is the
     * highest when reconciliation set difference is predictable. This queue is used to maintain the
     * order of peers chosen for reconciliation.
     */
    std::deque<NodeId> m_queue GUARDED_BY(m_mutex);

    public:

    std::tuple<bool, bool, uint32_t, uint64_t> SuggestReconciling(const NodeId peer_id, bool inbound)
    {
        bool be_recon_requestor, be_recon_responder;
        // Currently reconciliation requests flow only in one direction inbound->outbound.
        if (inbound) {
            be_recon_requestor = false;
            be_recon_responder = true;
        } else {
            be_recon_requestor = true;
            be_recon_responder = false;
        }

        uint32_t recon_version = 1;
        uint64_t m_local_recon_salt(GetRand(UINT64_MAX));
        WITH_LOCK(m_mutex, m_local_salts.emplace(peer_id, m_local_recon_salt));

        return std::make_tuple(be_recon_requestor, be_recon_responder, recon_version, m_local_recon_salt);
    }

    std::optional<bool> IsPeerChosenForFlooding(const NodeId peer_id) const
    {
        LOCK(m_mutex);
        auto recon_state = m_states.find(peer_id);
        if (recon_state == m_states.end()) {
            return std::nullopt;
        }
        return (*recon_state).second.m_flood_to;
    }

    bool EnableReconciliationSupport(const NodeId peer_id, bool inbound,
        bool recon_requestor, bool recon_responder, uint32_t recon_version, uint64_t remote_salt,
        size_t outbound_flooders)
    {
        // Do not support reconciliation salt/version updates
        LOCK(m_mutex);
        auto recon_state = m_states.find(peer_id);
        if (recon_state != m_states.end()) return false;

        if (recon_version != 1) return false;

        // Do not flood through inbound connections which support reconciliation to save bandwidth.
        // Flood only through a limited number of outbound connections.
        bool flood_to = false;
        if (inbound) {
            // We currently don't support reconciliations with inbound peers which
            // don't want to be reconciliation senders (request our sketches),
            // or want to be reconciliation responders (send us their sketches).
            // Just ignore SENDRECON and use normal flooding for transaction relay with them.
            if (!recon_requestor) return false;
            if (recon_responder) return false;
        } else {
            // We currently don't support reconciliations with outbound peers which
            // don't want to be reconciliation responders (send us their sketches),
            // or want to be reconciliation senders (request our sketches).
            // Just ignore SENDRECON and use normal flooding for transaction relay with them.
            if (recon_requestor) return false;
            if (!recon_responder) return false;
            // TODO: Flood only through a limited number of outbound connections.
            flood_to = true;
        }

        // Reconcile with all outbound peers supporting reconciliation (even if we flood to them),
        // to not miss transactions they have for us but won't flood.
        if (recon_responder) {
            m_queue.push_back(peer_id);
        }

        uint256 full_salt = ComputeSalt(m_local_salts.at(peer_id), remote_salt);

        m_states.emplace(peer_id, ReconciliationState(recon_requestor, recon_responder,
                            flood_to, full_salt.GetUint64(0), full_salt.GetUint64(1)));
        return true;
    }

};

TxReconciliationTracker::TxReconciliationTracker() :
    m_impl{MakeUnique<TxReconciliationTracker::Impl>()} {}

TxReconciliationTracker::~TxReconciliationTracker() = default;

std::tuple<bool, bool, uint32_t, uint64_t> TxReconciliationTracker::SuggestReconciling(const NodeId peer_id, bool inbound)
{
    return m_impl->SuggestReconciling(peer_id, inbound);
}

bool TxReconciliationTracker::EnableReconciliationSupport(const NodeId peer_id, bool inbound,
    bool recon_requestor, bool recon_responder, uint32_t recon_version, uint64_t remote_salt,
    size_t outbound_flooders)
{
    return m_impl->EnableReconciliationSupport(peer_id, inbound, recon_requestor, recon_responder,
        recon_version, remote_salt, outbound_flooders);
}

std::optional<bool> TxReconciliationTracker::IsPeerChosenForFlooding(const NodeId peer_id) const
{
    return m_impl->IsPeerChosenForFlooding(peer_id);
}
