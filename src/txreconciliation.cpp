// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <txreconciliation.h>

#include <unordered_map>
#include <util/hasher.h>

namespace {

/** Current protocol version */
constexpr uint32_t RECON_VERSION = 1;
/** Static component of the salt used to compute short txids for inclusion in sketches. */
const std::string RECON_STATIC_SALT = "Tx Relay Salting";
/** Announce transactions via full wtxid to a limited number of inbound and outbound peers. */
constexpr uint8_t INBOUND_FANOUT_DESTINATIONS = 2;
constexpr uint8_t OUTBOUND_FANOUT_DESTINATIONS = 2;

/**
 * Salt is specified by BIP-330 is constructed from contributions from both peers. It is later used
 * to compute transaction short IDs, which are needed to construct a sketch representing a set of
 * transactions we want to announce to the peer.
 */
uint256 ComputeSalt(uint64_t local_salt, uint64_t remote_salt)
{
    uint64_t salt1 = local_salt, salt2 = remote_salt;
    if (salt1 > salt2) std::swap(salt1, salt2);
    static const auto RECON_SALT_HASHER = TaggedHash(RECON_STATIC_SALT);
    return (CHashWriter(RECON_SALT_HASHER) << salt1 << salt2).GetSHA256();
}

/**
 * Keeps track of the transactions we want to announce to the peer along with the state
 * required to reconcile them.
 */
struct ReconciliationSet {
    /** Transactions we want to announce to the peer */
    std::set<uint256> m_wtxids;

    /** Get a number of transactions in the set. */
    size_t GetSize() const {
        return m_wtxids.size();
    }

    /** This should be called at the end of every reconciliation to avoid unbounded state growth. */
    void Clear() {
        m_wtxids.clear();
    }

};


/**
 * Used to keep track of the ongoing reconciliations, the transactions we want to announce to the
 * peer when next transaction reconciliation happens, and also all parameters required to perform
 * reconciliations.
 */
class ReconciliationState {

    /**
     * Reconciliation involves exchanging sketches, which efficiently represent transactions each
     * peer wants to announce. Sketches are computed over transaction short IDs.
     * These values are used to salt short IDs.
     */
    const uint64_t m_k0, m_k1;

    public:

    /**
     * Reconciliation protocol assumes using one role consistently: either a reconciliation
     * initiator (requesting sketches), or responder (sending sketches). This defines our role.
     * */
    const bool m_we_initiate;

    /**
     * Store all transactions which we would relay to the peer (policy checks passed, etc.)
     * in this set instead of announcing them right away. When reconciliation time comes, we will
     * compute an efficient representation of this set ("sketch") and use it to efficient reconcile
     * this set with a similar set on the other side of the connection.
     */
    ReconciliationSet m_local_set;

    ReconciliationState(uint64_t k0, uint64_t k1, bool we_initiate) :
        m_k0(k0), m_k1(k1), m_we_initiate(we_initiate) {}
};

} // namespace

/** Actual implementation for TxReconciliationTracker's data structure. */
class TxReconciliationTracker::Impl {

    mutable Mutex m_mutex;

    /**
     * We need a ReconciliationTracker-wide randomness to decide to which peers we should flood a
     * given transaction based on a (w)txid.
     */
    const SaltedTxidHasher txidHasher;


    /**
     * Per-peer salt is used to compute transaction short IDs, which will be later used to
     * construct reconciliation sketches.
     * Salt is generated randomly per-peer to prevent:
     * - linking of network nodes belonging to the same physical node
     * - halting of relay of particular transactions due to short ID collisions (DoS)
     */
    std::unordered_map<NodeId, uint64_t> m_local_salts GUARDED_BY(m_mutex);

    /**
     * Keeps track of ongoing reconciliations with a given peer.
     */
    std::unordered_map<NodeId, ReconciliationState> m_states GUARDED_BY(m_mutex);

    public:

    std::tuple<bool, bool, uint32_t, uint64_t> SuggestReconciling(NodeId peer_id, bool inbound)
    {
        bool we_initiate_recon, we_respond_recon;
        // Currently reconciliation roles are defined by the connection direction: only the inbound
        // peer initiate reconciliations and the outbound peer is supposed to only respond.
        if (inbound) {
            we_initiate_recon = false;
            we_respond_recon = true;
        } else {
            we_initiate_recon = true;
            we_respond_recon = false;
        }

        uint64_t m_local_recon_salt(GetRand(UINT64_MAX));
        bool added = WITH_LOCK(m_mutex, return m_local_salts.emplace(peer_id, m_local_recon_salt).second);
        // We do this exactly once per peer (which are unique by NodeId, see GetNewNodeId) so it's
        // safe to assume we don't have this record yet.
        assert(added);

        LogPrint(BCLog::NET, "Prepare to announce reconciliation support to peer=%d.\n", peer_id);

        return std::make_tuple(we_initiate_recon, we_respond_recon, RECON_VERSION, m_local_recon_salt);
    }

    bool EnableReconciliationSupport(NodeId peer_id, bool inbound,
        bool they_may_initiate, bool they_may_respond, uint32_t recon_version, uint64_t remote_salt)
    {
        // We do not support reconciliation salt/version updates. We treat an attempt to update
        // after a successful registration as a protocol violation.
        LOCK(m_mutex);
        if (m_states.find(peer_id) != m_states.end()) return false;

        // If the peer supports the version which is lower than our, we downgrade to the version
        // they support. For now, this only guarantees that nodes with future reconciliation
        // versions have the choice of reconciling with this current version. However, they also
        // have the choice to refuse supporting reconciliations if the common version is not
        // satisfactory (e.g. too low).
        recon_version = std::min(recon_version, RECON_VERSION);
        // v1 is the lowest version, so suggesting something below must be a protocol violation.
        if (recon_version < 1) return false;

        auto local_salt = m_local_salts.find(peer_id);

        // This function should be called only after generating the local salt.
        if (local_salt == m_local_salts.end()) return false;

        // Must match SuggestReconciling logic.
        bool we_may_initiate = !inbound, we_may_respond = inbound;

        bool they_initiate = they_may_initiate && we_may_respond;
        bool we_initiate = we_may_initiate && they_may_respond;
        // If we ever announce we_initiate && we_may_respond, this will need tie-breaking. For now,
        // this is mutually exclusive because both are based on the inbound flag.
        assert(!(they_initiate && we_initiate));

        // The peer set both flags to false, we treat it as a protocol violation.
        if (!(they_initiate || we_initiate)) return false;

        LogPrint(BCLog::NET, "Register peer=%d for reconciliation with the following params: " /* Continued */
            "we_initiate=%i, they_initiate=%i.\n", peer_id, we_initiate, they_initiate);

        uint256 full_salt = ComputeSalt(local_salt->second, remote_salt);

        assert(m_states.emplace(peer_id, ReconciliationState(full_salt.GetUint64(0),
            full_salt.GetUint64(1), we_initiate)).second);
        return true;
    }

    void AddToReconSet(NodeId peer_id, const std::vector<uint256>& txs_to_reconcile)
    {
        assert(txs_to_reconcile.size() > 0);
        LOCK(m_mutex);
        auto recon_state = m_states.find(peer_id);
        assert(recon_state != m_states.end());

        size_t added = 0;
        for (auto& wtxid: txs_to_reconcile) {
            if (recon_state->second.m_local_set.m_wtxids.insert(wtxid).second) {
                ++added;
            }
        }

        LogPrint(BCLog::NET, "Added %i new transactions to the reconciliation set for peer=%d. " /* Continued */
            "Now the set contains %i transactions.\n", added, peer_id, recon_state->second.m_local_set.GetSize());
    }

    void TryRemovingFromReconSet(NodeId peer_id, const uint256 wtxid_to_remove)
    {
        LOCK(m_mutex);
        auto recon_state = m_states.find(peer_id);
        if (recon_state == m_states.end()) return;

        recon_state->second.m_local_set.m_wtxids.erase(wtxid_to_remove);
    }

    void RemovePeer(NodeId peer_id)
    {
        LOCK(m_mutex);
        auto salt_erased = m_local_salts.erase(peer_id);
        auto state_erased = m_states.erase(peer_id);
        if (salt_erased || state_erased) {
            LogPrint(BCLog::NET, "Stop tracking reconciliation state for peer=%d.\n", peer_id);
        }
    }

    bool IsPeerRegistered(NodeId peer_id) const
    {
        LOCK(m_mutex);
        return m_states.find(peer_id) != m_states.end();
    }

    std::optional<bool> IsPeerInitiator(NodeId peer_id) const
    {
        LOCK(m_mutex);
        auto recon_state = m_states.find(peer_id);
        if (recon_state == m_states.end()) {
            return std::nullopt;
        }
        return !recon_state->second.m_we_initiate;
    }

    std::optional<size_t> GetPeerSetSize(NodeId peer_id) const
    {
        LOCK(m_mutex);
        auto recon_state = m_states.find(peer_id);
        if (recon_state == m_states.end()) {
            return std::nullopt;
        }
        return recon_state->second.m_local_set.GetSize();
    }

    bool ShouldFloodTo(uint256 wtxid, NodeId peer_id) const
    {
        LOCK(m_mutex);

        auto recon_state = m_states.find(peer_id);
        if (recon_state == m_states.end()) {
            return false;
        }

        // In this function we make an assumption that reconciliation is always initiated from
        // inbound to outbound to avoid code complexity.
        size_t destinations;
        std::vector<NodeId> eligible_peers;
        if (recon_state->second.m_we_initiate) {
            std::for_each(m_states.begin(), m_states.end(),
                [&eligible_peers](std::pair<NodeId, ReconciliationState> state) {
                    if (state.second.m_we_initiate) eligible_peers.push_back(state.first);
                }
            );
            destinations = OUTBOUND_FANOUT_DESTINATIONS;
        } else {
            std::for_each(m_states.begin(), m_states.end(),
                [&eligible_peers](std::pair<NodeId, ReconciliationState> state) {
                    if (!state.second.m_we_initiate) eligible_peers.push_back(state.first);
                }
            );
            destinations = INBOUND_FANOUT_DESTINATIONS;
        }

        const auto it = std::find(eligible_peers.begin(), eligible_peers.end(), peer_id);
        assert(it != eligible_peers.end());

        size_t reverse_probability;
        if (eligible_peers.size() <= destinations) {
            // If we have fewer eligible peers than destinations, flood to each of them with 50%
            // chance.
            reverse_probability = 2;
        } else {
            reverse_probability = eligible_peers.size() / destinations;
        }

        const size_t peer_index = it - eligible_peers.begin();
        return txidHasher(wtxid) % reverse_probability == peer_index % reverse_probability;
    }

};

TxReconciliationTracker::TxReconciliationTracker() :
    m_impl{std::make_unique<TxReconciliationTracker::Impl>()} {}

TxReconciliationTracker::~TxReconciliationTracker() = default;

std::tuple<bool, bool, uint32_t, uint64_t> TxReconciliationTracker::SuggestReconciling(NodeId peer_id, bool inbound)
{
    return m_impl->SuggestReconciling(peer_id, inbound);
}

bool TxReconciliationTracker::EnableReconciliationSupport(NodeId peer_id, bool inbound,
    bool recon_requestor, bool recon_responder, uint32_t recon_version, uint64_t remote_salt)
{
    return m_impl->EnableReconciliationSupport(peer_id, inbound, recon_requestor, recon_responder,
        recon_version, remote_salt);
}

void TxReconciliationTracker::AddToReconSet(NodeId peer_id, const std::vector<uint256>& txs_to_reconcile)
{
    m_impl->AddToReconSet(peer_id, txs_to_reconcile);
}

void TxReconciliationTracker::TryRemovingFromReconSet(NodeId peer_id, const uint256 wtxid_to_remove)
{
    m_impl->TryRemovingFromReconSet(peer_id, wtxid_to_remove);
}

void TxReconciliationTracker::RemovePeer(NodeId peer_id)
{
    m_impl->RemovePeer(peer_id);
}

bool TxReconciliationTracker::IsPeerRegistered(NodeId peer_id) const
{
    return m_impl->IsPeerRegistered(peer_id);
}

std::optional<bool> TxReconciliationTracker::IsPeerInitiator(NodeId peer_id) const
{
    return m_impl->IsPeerInitiator(peer_id);
}

std::optional<size_t> TxReconciliationTracker::GetPeerSetSize(NodeId peer_id) const
{
    return m_impl->GetPeerSetSize(peer_id);
}

bool TxReconciliationTracker::ShouldFloodTo(uint256 wtxid, NodeId peer_id) const
{
    return m_impl->ShouldFloodTo(wtxid, peer_id);
}
