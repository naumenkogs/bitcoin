// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/txreconciliation.h>

#include <common/system.h>
#include <logging.h>
#include <node/minisketchwrapper.h>
#include <util/check.h>
#include <util/hasher.h>

#include <cmath>
#include <unordered_map>
#include <variant>


namespace {

/** Static salt component used to compute short txids for sketch construction, see BIP-330. */
const std::string RECON_STATIC_SALT = "Tx Relay Salting";
const HashWriter RECON_SALT_HASHER = TaggedHash(RECON_STATIC_SALT);
/**
 * Announce transactions via full wtxid to a limited number of inbound and outbound peers.
 * Justification for these values are provided here:
 * https://github.com/naumenkogs/txrelaysim/issues/7#issuecomment-902165806 */
constexpr double INBOUND_FANOUT_DESTINATIONS_FRACTION = 0.1;
constexpr size_t OUTBOUND_FANOUT_DESTINATIONS = 1;

/**
 * Maximum number of transactions for which we store assigned fanout targets.
 */
constexpr size_t FANOUT_TARGETS_PER_TX_CACHE_SIZE = 3000;
/** The size of the field, used to compute sketches to reconcile transactions (see BIP-330). */
constexpr unsigned int RECON_FIELD_SIZE = 32;
/**
 * Allows to infer capacity of a reconciliation sketch based on it's char[] representation,
 * which is necessary to deserealize a received sketch.
 */
constexpr unsigned int BYTES_PER_SKETCH_CAPACITY = RECON_FIELD_SIZE / 8;
/**
 * Limit sketch capacity to avoid DoS. This applies only to the original sketches,
 * and implies that extended sketches could be at most twice the size.
 */
constexpr uint32_t MAX_SKETCH_CAPACITY = 2 << 12;

/**
 * It is possible that if sketch encodes more elements than the capacity, or
 * if it is constructed of random bytes, sketch decoding may "succeed",
 * but the result will be nonsense (false-positive decoding).
 * Given this coef, a false positive probability will be of 1 in 2**coef.
 */
constexpr unsigned int RECON_FALSE_POSITIVE_COEF = 16;
static_assert(RECON_FALSE_POSITIVE_COEF <= 256,
              "Reducing reconciliation false positives beyond 1 in 2**256 is not supported");
/**
 * A floating point coefficient q for estimating reconciliation set difference, and
 * the value used to convert it to integer for transmission purposes, as specified in BIP-330.
 */
constexpr double Q = 0.25;
constexpr uint16_t Q_PRECISION{(2 << 14) - 1};
/**
 * Interval between initiating reconciliations with peers.
 * This value allows to reconcile ~(7 tx/s * 8s) transactions during normal operation.
 * More frequent reconciliations would cause significant constant bandwidth overhead
 * due to reconciliation metadata (sketch sizes etc.), which would nullify the efficiency.
 * Less frequent reconciliations would introduce high transaction relay latency.
 */
constexpr std::chrono::microseconds RECON_REQUEST_INTERVAL{8s};
/**
 * We should keep an interval between responding to reconciliation requests from the same peer,
 * to reduce potential DoS surface.
 */
constexpr std::chrono::microseconds RECON_RESPONSE_INTERVAL{1s};

/**
 * Represents phase of the current reconciliation round with a peer.
 */
enum class Phase {
    NONE,
    INIT_REQUESTED,
    INIT_RESPONDED,
    EXT_REQUESTED
};

/**
 * Salt (specified by BIP-330) constructed from contributions from both peers. It is used
 * to compute transaction short IDs, which are then used to construct a sketch representing a set
 * of transactions we want to announce to the peer.
 */
uint256 ComputeSalt(uint64_t salt1, uint64_t salt2)
{
    // According to BIP-330, salts should be combined in ascending order.
    return (HashWriter(RECON_SALT_HASHER) << std::min(salt1, salt2) << std::max(salt1, salt2)).GetSHA256();
}

/**
 * Keeps track of txreconciliation-related per-peer state.
 */
class TxReconciliationState
{
public:
    /**
     * Reconciliation protocol assumes using one role consistently: either a reconciliation
     * initiator (requesting sketches), or responder (sending sketches). This defines our role,
     * based on the direction of the p2p connection.
     *
     */
    bool m_we_initiate;

    /**
     * These values are used to salt short IDs, which is necessary for transaction reconciliations.
     */
    uint64_t m_k0, m_k1;

    /**
     * A reconciliation round may involve an extension, in which case we should remember
     * a capacity of the sketch sent out initially, so that a sketch extension is of the same size.
     */
    uint16_t m_capacity_snapshot{0};

    /** Keep track of the reconciliation phase with the peer. */
    Phase m_phase{Phase::NONE};

    /**
     * The following fields are specific to only reconciliations initiated by the peer.
     */

    /**
     * The use of q coefficients is described above (see local_q comment).
     * The value transmitted from the peer with a reconciliation requests is stored here until
     * we respond to that request with a sketch.
     */
    double m_remote_q{Q};

    /**
     * A reconciliation request comes from a peer with a reconciliation set size from their side,
     * which is supposed to help us to estimate set difference size. The value is stored here until
     * we respond to that request with a sketch.
     */
    uint16_t m_remote_set_size;

    /**
    * Set of transactions to be added to the reconciliation set (moved to m_local_set) upon the trickle.
    */
    std::unordered_set<Wtxid, SaltedTxidHasher> m_delayed_local_set;

    /**
     * We track when was the last time we responded to a reconciliation request by the peer,
     * so that we don't respond to them too often. This helps to reduce DoS surface.
     */
    std::chrono::microseconds m_last_init_recon_respond{0};
    /**
     * Returns whether at this time it's not too early to respond to a reconciliation request by
     * the peer, and, if so, bumps the time we last responded to allow further checks.
     */
    bool ConsiderInitResponseAndTrack()
    {
        auto current_time = GetTime<std::chrono::seconds>();
        if (m_last_init_recon_respond <= current_time - RECON_RESPONSE_INTERVAL) {
            m_last_init_recon_respond = current_time;
            return true;
        }
        return false;
    }

    /**
     * Store all wtxids which we would announce to the peer (policy checks passed, etc.)
     * in this set instead of announcing them right away. When reconciliation time comes, we will
     * compute a compressed representation of this set ("sketch") and use it to efficiently
     * reconcile this set with a set on the peer's side.
     */
    std::unordered_set<Wtxid, SaltedTxidHasher> m_local_set;

    /**
     * Reconciliation sketches are computed over short transaction IDs.
     * This is a cache of these IDs enabling faster lookups of full wtxids,
     * useful when peer will ask for missing transactions by short IDs
     * at the end of a reconciliation round.
     * We also use this to keep track of short ID collisions. In case of a
     * collision, both transactions should be fanout.
     */
    std::map<uint32_t, Wtxid> m_short_id_mapping;

    TxReconciliationState(bool we_initiate, uint64_t k0, uint64_t k1) : m_we_initiate(we_initiate), m_k0(k0), m_k1(k1), m_delayed_local_set(), m_local_set(0, m_delayed_local_set.hash_function()) {}

    /**
    * Checks whether a transaction is already in the set. If `include_delayed` is set, the delayed set is also
    * checked. Otherwise, transactions are only looked up in the regular set.
    */
    bool ContainsTx(const Wtxid& wtxid, bool include_delayed)
    {
        bool found = m_local_set.find(wtxid) != m_local_set.end();
        if (include_delayed) {
            found |= m_delayed_local_set.find(wtxid) != m_delayed_local_set.end();
        }

        return found;
    }

    /**
     * Returns a pair of sizes, corresponding to the reconciliation set and the delayed transactions set
     */
    std::pair<size_t, size_t> ReconSetSize()
    {
        return std::make_pair(m_local_set.size(), m_delayed_local_set.size());
    }

    bool RemoveFromSet(const Wtxid& wtxid)
    {
        if (m_local_set.contains(wtxid)) {
            Assume(!m_delayed_local_set.contains(wtxid));
            return m_local_set.erase(wtxid);
        } else {
            return m_delayed_local_set.erase(wtxid);
        }
    }
    /**
     * A reconciliation round may involve an extension, which is an extra exchange of messages.
     * Since it may happen after a delay (at least network latency), new transactions may come
     * during that time. To avoid mixing old and new transactions, those which are subject for
     * extension of a current reconciliation round are moved to a reconciliation set snapshot
     * after an initial (non-extended) sketch is sent.
     * New transactions are kept in the regular reconciliation set.
     */
    std::unordered_set<Wtxid, SaltedTxidHasher> m_local_set_snapshot;
    /** Same as non-snapshot set above */
    std::map<uint32_t, Wtxid> m_snapshot_short_id_mapping;

    /**
     * In a reconciliation round initiated by us, if we asked for an extension, we want to store
     * the sketch computed/transmitted in the initial step, so that we can use it when
     * sketch extension arrives.
     */
    std::vector<uint8_t> m_remote_sketch_snapshot;

    /**
     * Reconciliation sketches are computed over short transaction IDs.
     * Short IDs are salted with a link-specific constant value.
     */
    uint32_t ComputeShortID(const uint256 wtxid) const
    {
        const uint64_t s = SipHashUint256(m_k0, m_k1, wtxid);
        const uint32_t short_txid = 1 + (s & 0xFFFFFFFF);
        return short_txid;
    }

    /**
     * Estimate a capacity of a sketch we will send or use locally (to find set difference)
     * based on the local set size.
     */
    uint32_t EstimateSketchCapacity(size_t local_set_size) const
    {
        const uint16_t set_size_diff = std::abs(uint16_t(local_set_size) - m_remote_set_size);
        const uint16_t min_size = std::min(uint16_t(local_set_size), m_remote_set_size);
        const uint16_t weighted_min_size = m_remote_q * min_size;
        const uint32_t estimated_diff = 1 + weighted_min_size + set_size_diff;
        return minisketch_compute_capacity(RECON_FIELD_SIZE, estimated_diff, RECON_FALSE_POSITIVE_COEF);
    }

    /**
     * Reconciliation involves computing a space-efficient representation of transaction identifiers
     * (a sketch). A sketch has a capacity meaning it allows reconciling at most a certain number
     * of elements (see BIP-330).
     */
    Minisketch ComputeBaseSketch(uint32_t& capacity)
    {
        Minisketch sketch;
        // Avoid serializing/sending an empty sketch.
        if (capacity == 0) return sketch;

        // To be used for sketch extension of the exact same size.
        m_capacity_snapshot = capacity;

        capacity = std::min(capacity, MAX_SKETCH_CAPACITY);
        sketch = node::MakeMinisketch32(capacity);

        for (const auto& wtxid : m_local_set) {
            uint32_t short_txid = ComputeShortID(wtxid);
            sketch.Add(short_txid);
            m_short_id_mapping.emplace(short_txid, wtxid);
        }

        return sketch;
    }

    /**
     * When our peer tells us that our sketch was insufficient to reconcile transactions because
     * of the low capacity, we compute an extended sketch with the double capacity, and then send
     * only the part the peer is missing to that peer.
     */
    Minisketch ComputeExtendedSketch(uint32_t extended_capacity)
    {
        assert(extended_capacity > 0);
        // This can't happen because we should have terminated reconciliation early.
        assert(m_local_set_snapshot.size() > 0);

        // For now, compute a sketch of twice the capacity were computed originally.
        // TODO: optimize by computing the extension *on top* of the existent sketch
        // instead of computing the lower order elements again.
        Minisketch sketch = Minisketch(RECON_FIELD_SIZE, 0, extended_capacity);

        // We don't have to recompute short IDs here.
        for (const auto& shortid_to_wtxid : m_snapshot_short_id_mapping) {
            sketch.Add(shortid_to_wtxid.first);
        }
        return sketch;
    }

    /**
     * Be ready to respond to extension request, to compute the extended sketch over
     * the same initial set (without transactions received during the reconciliation).
     * Allow to store new transactions separately in the original set.
     */
    void PrepareForExtensionRequest(uint16_t sketch_capacity)
    {
        assert(!m_we_initiate);
        m_capacity_snapshot = sketch_capacity;
        // FIXME: This is a hack to copy one set to the other, needs to be done properly
        for (auto txid: m_local_set) {
            m_local_set_snapshot.emplace(txid);
        }
        //m_local_set_snapshot = m_local_set;
        m_snapshot_short_id_mapping = m_short_id_mapping;
        m_local_set.clear();
        m_short_id_mapping.clear();
    }

    std::vector<uint256> GetAllTransactions() const
    {
        return std::vector<uint256>(m_local_set.begin(), m_local_set.end());
    }


    /**
     * When during reconciliation we find a set difference successfully (by combining sketches),
     * we want to find which transactions are missing on our and on their side.
     * For those missing on our side, we may only find short IDs.
     */
    void GetRelevantIDsFromShortIDs(const std::vector<uint64_t>& diff,
        // returning values
        std::vector<uint32_t>& local_missing, std::vector<uint256>& remote_missing) const
    {
        for (const auto& diff_short_id: diff) {
            const auto local_tx = m_short_id_mapping.find(diff_short_id);
            if (local_tx != m_short_id_mapping.end()) {
                remote_missing.push_back(local_tx->second);
            } else {
                local_missing.push_back(diff_short_id);
            }
        }
    }

    /**
     * To be efficient in transmitting extended sketch, we store a snapshot of the sketch
     * received in the initial reconciliation step, so that only the necessary extension data
     * has to be transmitted.
     * We also store a snapshot of our local reconciliation set, to better keep track of
     * transactions arriving during this reconciliation (they will be added to the cleared
     * original reconciliation set, to be reconciled next time).
     */
    void PrepareForExtensionResponse(uint16_t sketch_capacity, const std::vector<uint8_t>& remote_sketch)
    {
        assert(m_we_initiate);
        m_capacity_snapshot = sketch_capacity;
        m_remote_sketch_snapshot = remote_sketch;
        // FIXME: This is a hack to copy one set to the other, needs to be done properly
        for (auto txid: m_local_set) {
            m_local_set_snapshot.emplace(txid);
        }
        // m_local_set_snapshot = m_local_set
        m_snapshot_short_id_mapping = m_short_id_mapping;
        m_local_set.clear();
        m_short_id_mapping.clear();
    }
};
} // namespace

/** Actual implementation for TxReconciliationTracker's data structure. */
class TxReconciliationTracker::Impl
{
private:
    mutable Mutex m_txreconciliation_mutex;

    // Local protocol version
    uint32_t m_recon_version;

    /**
     * Keeps track of txreconciliation states of eligible peers.
     * For pre-registered peers, the locally generated salt is stored.
     * For registered peers, the locally generated salt is forgotten, and the state (including
     * "full" salt) is stored instead.
     */
    std::unordered_map<NodeId, std::variant<uint64_t, TxReconciliationState>> m_states GUARDED_BY(m_txreconciliation_mutex);

    /*
     * Keeps track of how many of the registered peers are inbound. Updated on registering or
     * forgetting peers.
     */
    size_t m_inbounds_count GUARDED_BY(m_txreconciliation_mutex){0};

    /**
     * Maintains a queue of reconciliations we should initiate. To achieve higher bandwidth
     * conservation and avoid overflows, we should reconcile in the same order, because then it’s
     * easier to estimate set difference size.
     */
    std::deque<NodeId> m_queue GUARDED_BY(m_txreconciliation_mutex);

    /**
     * Make reconciliation requests periodically to make reconciliations efficient.
     */
    std::chrono::microseconds m_next_recon_request GUARDED_BY(m_txreconciliation_mutex){0};

    // Used for randomly choosing fanout targets.
    CSipHasher m_deterministic_randomizer;

    TxReconciliationState* GetRegisteredPeerState(NodeId peer_id) EXCLUSIVE_LOCKS_REQUIRED(m_txreconciliation_mutex)
    {
        AssertLockHeld(m_txreconciliation_mutex);
        auto salt_or_state = m_states.find(peer_id);
        if (salt_or_state == m_states.end()) return nullptr;

        return std::get_if<TxReconciliationState>(&salt_or_state->second);
    }

    void UpdateNextReconRequest(std::chrono::microseconds now) EXCLUSIVE_LOCKS_REQUIRED(m_txreconciliation_mutex)
    {
        // We have one timer for the entire queue. This is safe because we initiate reconciliations
        // with outbound connections, which are unlikely to game this timer in a serious way.
        size_t we_initiate_to_count = std::count_if(m_states.begin(), m_states.end(),
                                                    [](std::pair<NodeId, std::variant<uint64_t, TxReconciliationState>> indexed_state) {
                                                        const auto* cur_state = std::get_if<TxReconciliationState>(&indexed_state.second);
                                                        if (cur_state) return cur_state->m_we_initiate;
                                                        return false;
                                                    });

        Assert(we_initiate_to_count != 0);
        m_next_recon_request = now + (RECON_REQUEST_INTERVAL / we_initiate_to_count);
    }

    bool HandleInitialSketch(TxReconciliationState& recon_state, const NodeId peer_id,
                             const std::vector<uint8_t>& skdata,
                             // returning values
                             std::vector<uint32_t>& txs_to_request, std::vector<uint256>& txs_to_announce, std::optional<bool>& result)
    {
        assert(recon_state.m_we_initiate);
        assert(recon_state.m_phase == Phase::INIT_REQUESTED);

        uint32_t remote_sketch_capacity = uint32_t(skdata.size() / BYTES_PER_SKETCH_CAPACITY);
        // Protocol violation: our peer exceeded the sketch capacity, or sent a malformed sketch.
        if (remote_sketch_capacity > MAX_SKETCH_CAPACITY) {
            return false;
        }

        Minisketch local_sketch, remote_sketch;
        if (recon_state.m_local_set.size() > 0) {
            local_sketch = recon_state.ComputeBaseSketch(remote_sketch_capacity);
        }
        if (remote_sketch_capacity != 0) {
            remote_sketch = node::MakeMinisketch32(remote_sketch_capacity).Deserialize(skdata);
        }

        // Remote sketch is empty in two cases per which reconciliation is pointless:
        // 1. the peer has no transactions for us
        // 2. we told the peer we have no transactions for them while initiating reconciliation.
        // In case (2), local sketch is also empty.
        if (remote_sketch_capacity == 0 || !remote_sketch || !local_sketch) {
            // Announce all transactions we have.
            txs_to_announce = recon_state.GetAllTransactions();

            // Update local reconciliation state for the peer.
            recon_state.m_local_set.clear();
            recon_state.m_phase = Phase::NONE;

            result = false;

            LogPrintLevel(BCLog::TXRECONCILIATION, BCLog::Level::Debug, "Reconciliation we initiated with peer=%d terminated due to empty sketch. "
                                 "Announcing all %i transactions from the local set.\n",
                     peer_id, txs_to_announce.size());

            return true;
        }

        assert(remote_sketch);
        assert(local_sketch);
        // Attempt to decode the set difference
        size_t max_elements = minisketch_compute_max_elements(RECON_FIELD_SIZE, remote_sketch_capacity, RECON_FALSE_POSITIVE_COEF);
        std::vector<uint64_t> differences(max_elements);
        if (local_sketch.Merge(remote_sketch).Decode(differences)) {
            // Initial reconciliation step succeeded.

            // Identify locally/remotely missing transactions.
            recon_state.GetRelevantIDsFromShortIDs(differences, txs_to_request, txs_to_announce);

            // Update local reconciliation state for the peer.
            recon_state.m_local_set.clear();
            recon_state.m_phase = Phase::NONE;

            result = true;
            LogPrintLevel(BCLog::TXRECONCILIATION, BCLog::Level::Debug, "Reconciliation we initiated with peer=%d has succeeded at initial step, "
                                 "request %i txs, announce %i txs.\n",
                     peer_id, txs_to_request.size(), txs_to_announce.size());
        } else {
            // Initial reconciliation step failed.

            // Update local reconciliation state for the peer.
            recon_state.PrepareForExtensionResponse(remote_sketch_capacity, skdata);
            recon_state.m_phase = Phase::EXT_REQUESTED;

            result = std::nullopt;

            LogPrintLevel(BCLog::TXRECONCILIATION, BCLog::Level::Debug, "Reconciliation we initiated with peer=%d has failed at initial step, "
                "request sketch extension.\n", peer_id);
        }
        return true;
    }

public:
    explicit Impl(uint32_t recon_version, CSipHasher hasher) : m_recon_version(recon_version), m_deterministic_randomizer(std::move(hasher)) {}

    uint64_t PreRegisterPeer(NodeId peer_id, uint64_t local_salt) EXCLUSIVE_LOCKS_REQUIRED(!m_txreconciliation_mutex)
    {
        AssertLockNotHeld(m_txreconciliation_mutex);
        LOCK(m_txreconciliation_mutex);

        LogPrintLevel(BCLog::TXRECONCILIATION, BCLog::Level::Debug, "Pre-register peer=%d\n", peer_id);
        // We do this exactly once per peer (which are unique by NodeId, see GetNewNodeId) so it's
        // safe to assume we don't have this record yet.
        Assume(m_states.emplace(peer_id, local_salt).second);
        return local_salt;
    }

    ReconciliationRegisterResult RegisterPeer(NodeId peer_id, bool is_peer_inbound, uint32_t peer_recon_version,
                                              uint64_t remote_salt) EXCLUSIVE_LOCKS_REQUIRED(!m_txreconciliation_mutex)
    {
        AssertLockNotHeld(m_txreconciliation_mutex);
        LOCK(m_txreconciliation_mutex);
        auto recon_state = m_states.find(peer_id);

        if (recon_state == m_states.end()) return ReconciliationRegisterResult::NOT_FOUND;

        if (std::holds_alternative<TxReconciliationState>(recon_state->second)) {
            return ReconciliationRegisterResult::ALREADY_REGISTERED;
        }

        uint64_t local_salt = *std::get_if<uint64_t>(&recon_state->second);

        // If the peer supports the version which is lower than ours, we downgrade to the version
        // it supports. For now, this only guarantees that nodes with future reconciliation
        // versions have the choice of reconciling with this current version. However, they also
        // have the choice to refuse supporting reconciliations if the common version is not
        // satisfactory (e.g. too low).
        const uint32_t recon_version{std::min(peer_recon_version, m_recon_version)};
        // v1 is the lowest version, so suggesting something below must be a protocol violation.
        if (recon_version < 1) return ReconciliationRegisterResult::PROTOCOL_VIOLATION;

        LogPrintLevel(BCLog::TXRECONCILIATION, BCLog::Level::Debug, "Register peer=%d (inbound=%i)\n",
                      peer_id, is_peer_inbound);

        const uint256 full_salt{ComputeSalt(local_salt, remote_salt)};

        auto new_state = TxReconciliationState(!is_peer_inbound, full_salt.GetUint64(0), full_salt.GetUint64(1));;
        m_states.erase(recon_state);
        bool emplaced = m_states.emplace(peer_id, std::move(new_state)).second;
        Assume(emplaced);

        if (is_peer_inbound && m_inbounds_count < std::numeric_limits<size_t>::max()) {
            ++m_inbounds_count;
        }
        if (!is_peer_inbound) m_queue.push_back(peer_id);
        return ReconciliationRegisterResult::SUCCESS;
    }

    bool HasCollision(TxReconciliationState *peer_state, const Wtxid& wtxid, Wtxid& collision, uint32_t &short_id) EXCLUSIVE_LOCKS_REQUIRED(m_txreconciliation_mutex)
    {
        AssertLockHeld(m_txreconciliation_mutex);

        short_id = peer_state->ComputeShortID(wtxid);
        const auto iter = peer_state->m_short_id_mapping.find(short_id);

        if (iter != peer_state->m_short_id_mapping.end()) {
            collision = iter->second;
            return true;
        }

        return false;
    }

    AddToSetResult AddToSet(NodeId peer_id, const Wtxid& wtxid) EXCLUSIVE_LOCKS_REQUIRED(!m_txreconciliation_mutex)
    {
        AssertLockNotHeld(m_txreconciliation_mutex);
        LOCK(m_txreconciliation_mutex);
        auto peer_state = GetRegisteredPeerState(peer_id);
        if (!peer_state) return AddToSetResult::Failed();

        // Bypass if the wtxid is already in the set
        if (peer_state->ContainsTx(wtxid, /*include_delayed=*/true)) {
            LogPrintLevel(BCLog::TXRECONCILIATION, BCLog::Level::Debug, "%s already in reconciliation set for peer=%d. Bypassing.\n",
                          wtxid.ToString(), peer_id);
            return AddToSetResult::Succeeded();
        }

        // Make sure there is no short id collision between the wtxid we are trying to add
        // and any existing one in the reconciliation set
        Wtxid collision;
        uint32_t short_id;
        if (HasCollision(peer_state, wtxid, collision, short_id)) {
            return AddToSetResult::Collision(collision);
        }

        // Check if the reconciliation set is not at capacity for two reasons:
        // - limit sizes of reconciliation sets and short id mappings;
        // - limit CPU use for sketch computations.
        //
        // Since we reconcile frequently, reaching capacity either means:
        // (1) a peer for some reason does not request reconciliations from us for a long while, or
        // (2) really a lot of valid fee-paying transactions were dumped on us at once.
        // We don't care about a laggy peer (1) because we probably can't help them even if we fanout transactions.
        // However, exploiting (2) should not prevent us from relaying certain transactions.
        //
        // Transactions which don't make it to the set due to the limit are announced via fan-out.
        auto [recon_set_size, delayed_set_size] = peer_state->ReconSetSize();
        if (recon_set_size + delayed_set_size >= MAX_RECONSET_SIZE) return AddToSetResult::Failed();

        // The caller currently keeps track of the per-peer transaction announcements, so it
        // should not attempt to add same tx to the set twice. However, if that happens, we will
        // simply ignore it.
        if (peer_state->m_delayed_local_set.insert(wtxid).second) {
            peer_state->m_short_id_mapping.emplace(short_id, wtxid);
            LogPrintLevel(BCLog::TXRECONCILIATION, BCLog::Level::Debug, "Added %s to the reconciliation set for peer=%d. "
                                                                        "Now the set contains %i reconcilable transactions"
                                                                        "(plus %i delayed transactions).\n",
                          wtxid.ToString(), peer_id, recon_set_size, delayed_set_size + 1);
        }
        return AddToSetResult::Succeeded();
    }

    bool ReadyDelayedTransactions(NodeId peer_id) EXCLUSIVE_LOCKS_REQUIRED(!m_txreconciliation_mutex)
    {
        AssertLockNotHeld(m_txreconciliation_mutex);
        LOCK(m_txreconciliation_mutex);
        auto peer_state = GetRegisteredPeerState(peer_id);
        if (!peer_state) return false;

        peer_state->m_local_set.merge(peer_state->m_delayed_local_set);
        // There should be no duplicates, so m_delayed_local_set should be emptied
        Assert(peer_state->m_delayed_local_set.empty());
        return true;
    }

    bool IsTransactionInSet(NodeId peer_id, const Wtxid& wtxid, bool include_delayed) EXCLUSIVE_LOCKS_REQUIRED(!m_txreconciliation_mutex)
    {
        AssertLockNotHeld(m_txreconciliation_mutex);
        LOCK(m_txreconciliation_mutex);
        auto peer_state = GetRegisteredPeerState(peer_id);
        if (!peer_state) return false;

        return peer_state->ContainsTx(wtxid, include_delayed);
    }

    bool TryRemovingFromSet(NodeId peer_id, const Wtxid& wtxid) EXCLUSIVE_LOCKS_REQUIRED(!m_txreconciliation_mutex)
    {
        AssertLockNotHeld(m_txreconciliation_mutex);
        LOCK(m_txreconciliation_mutex);
        auto peer_state = GetRegisteredPeerState(peer_id);
        if (!peer_state) return false;

        auto removed = peer_state->RemoveFromSet(wtxid);
        if (removed) {
            auto [recon_set_size, delayed_set_size] = peer_state->ReconSetSize();
            peer_state->m_short_id_mapping.erase(peer_state->ComputeShortID(wtxid));
            LogPrintLevel(BCLog::TXRECONCILIATION, BCLog::Level::Debug, "Removed %s from the reconciliation set for peer=%d. "
                                                                        "Now the set contains %i reconcilable transactions"
                                                                        "(plus %i delayed transactions).\n",
                          wtxid.ToString(), peer_id, recon_set_size, delayed_set_size);
        } else {
            LogPrintLevel(BCLog::TXRECONCILIATION, BCLog::Level::Debug, "Couldn't remove %s from the reconciliation set for peer=%d. "
                                                                        "Transaction not found\n",
                          wtxid.ToString(), peer_id);
        }

        return removed;
    }

    bool IsPeerNextToReconcileWith(NodeId peer_id, std::chrono::microseconds now) EXCLUSIVE_LOCKS_REQUIRED(!m_txreconciliation_mutex)
    {
        AssertLockNotHeld(m_txreconciliation_mutex);
        LOCK(m_txreconciliation_mutex);

        if (!GetRegisteredPeerState(peer_id)) return false;
        if (m_queue.empty()) return false;

        const auto& recon_state = std::get<TxReconciliationState>(m_states.find(peer_id)->second);

        if (m_next_recon_request <= now && m_queue.front() == peer_id) {
            Assume(recon_state.m_we_initiate);
            m_queue.pop_front();
            m_queue.push_back(peer_id);

            // If the phase is not NONE, the peer hasn't responded to the previous reconciliation.
            // A laggy peer should not affect other peers.
            //
            // This doesn't prevent from a malicious peer gaming this by staying in this state
            // all the time somehow.
            if (recon_state.m_phase == Phase::NONE) UpdateNextReconRequest(now);
            return true;
        }

        return false;
    }

    std::optional<std::pair<uint16_t, uint16_t>> InitiateReconciliationRequest(NodeId peer_id) EXCLUSIVE_LOCKS_REQUIRED(!m_txreconciliation_mutex)
    {
        AssertLockNotHeld(m_txreconciliation_mutex);
        LOCK(m_txreconciliation_mutex);
        if (!GetRegisteredPeerState(peer_id)) return std::nullopt;

        auto& recon_state = std::get<TxReconciliationState>(m_states.find(peer_id)->second);
        if (!recon_state.m_we_initiate) return std::nullopt;

        if (recon_state.m_phase != Phase::NONE) return std::nullopt;
        recon_state.m_phase = Phase::INIT_REQUESTED;

        size_t local_set_size = recon_state.m_local_set.size();

        LogPrintLevel(BCLog::TXRECONCILIATION, BCLog::Level::Debug, "Initiate reconciliation with peer=%d with the following params: " /* Continued */
                                                                    "local_set_size=%i\n",
                      peer_id, local_set_size);

        // In future, Q could be recomputed after every reconciliation based on the
        // set differences. For now, it provides good enough results without recompute
        // complexity, but we communicate it here to allow backward compatibility if
        // the value is changed or made dynamic.
        return std::make_pair(local_set_size, Q * Q_PRECISION);
    }

    void HandleReconciliationRequest(NodeId peer_id, uint16_t peer_recon_set_size, uint16_t peer_q) EXCLUSIVE_LOCKS_REQUIRED(!m_txreconciliation_mutex)
    {
        AssertLockNotHeld(m_txreconciliation_mutex);
        LOCK(m_txreconciliation_mutex);
        if (!GetRegisteredPeerState(peer_id)) return;
        auto& recon_state = std::get<TxReconciliationState>(m_states.find(peer_id)->second);
        if (recon_state.m_we_initiate) return;
        if (recon_state.m_phase != Phase::NONE) return;

        double peer_q_converted = peer_q * 1.0 / Q_PRECISION;
        recon_state.m_remote_q = peer_q_converted;
        recon_state.m_remote_set_size = peer_recon_set_size;
        recon_state.m_phase = Phase::INIT_REQUESTED;

        LogPrintLevel(BCLog::TXRECONCILIATION, BCLog::Level::Debug, "Reconciliation initiated by peer=%d with the following params: "
                             "remote_q=%d, remote_set_size=%i.\n",
                 peer_id, peer_q_converted, peer_recon_set_size);
    }

    bool RespondToReconciliationRequest(NodeId peer_id, std::vector<uint8_t>& skdata) EXCLUSIVE_LOCKS_REQUIRED(!m_txreconciliation_mutex)
    {
        AssertLockNotHeld(m_txreconciliation_mutex);
        LOCK(m_txreconciliation_mutex);
        if (!GetRegisteredPeerState(peer_id)) return false;
        auto& recon_state = std::get<TxReconciliationState>(m_states.find(peer_id)->second);
        if (recon_state.m_we_initiate) return false;

        Phase incoming_phase = recon_state.m_phase;

        // For initial requests we have an extra check to avoid short intervals between responses
        // to the same peer (see comments in the check function for justification).
        bool respond_to_initial_request = incoming_phase == Phase::INIT_REQUESTED &&
                                          recon_state.ConsiderInitResponseAndTrack();
        if (!respond_to_initial_request) {
            return false;
        }

        // Compute a sketch over the local reconciliation set.
        uint32_t sketch_capacity = 0;

        // We send an empty vector at initial request in the following 2 cases because
        // reconciliation can't help:
        // - if we have nothing on our side
        // - if they have nothing on their side
        // Then, they will terminate reconciliation early and force flooding-style announcement.
        if (recon_state.m_remote_set_size > 0 && recon_state.m_local_set.size() > 0) {

            sketch_capacity = recon_state.EstimateSketchCapacity(
                recon_state.m_local_set.size());
            Minisketch sketch = recon_state.ComputeBaseSketch(sketch_capacity);
            if (sketch) skdata = sketch.Serialize();
        }

        recon_state.m_phase = Phase::INIT_RESPONDED;
        recon_state.PrepareForExtensionRequest(sketch_capacity);

        LogPrintLevel(BCLog::TXRECONCILIATION, BCLog::Level::Debug, "Responding with a sketch to reconciliation initiated by peer=%d: "
                             "sending sketch of capacity=%i.\n",
                 peer_id, sketch_capacity);

        return true;
    }

    bool HandleSketch(NodeId peer_id, const std::vector<uint8_t>& skdata,
                      // returning values
                      std::vector<uint32_t>& txs_to_request, std::vector<uint256>& txs_to_announce, std::optional<bool>& result) EXCLUSIVE_LOCKS_REQUIRED(!m_txreconciliation_mutex)
    {
        AssertLockNotHeld(m_txreconciliation_mutex);
        LOCK(m_txreconciliation_mutex);
        if (!GetRegisteredPeerState(peer_id)) return false;
        auto& recon_state = std::get<TxReconciliationState>(m_states.find(peer_id)->second);
        // We only may receive a sketch from reconciliation responder, not initiator.
        if (!recon_state.m_we_initiate) return false;

        Phase cur_phase = recon_state.m_phase;
        if (cur_phase == Phase::INIT_REQUESTED) {
            return HandleInitialSketch(recon_state, peer_id, skdata, txs_to_request, txs_to_announce, result);
        } else {
            LogPrintLevel(BCLog::TXRECONCILIATION, BCLog::Level::Debug, "Received sketch from peer=%d in wrong reconciliation phase=%i.\n", peer_id, static_cast<int>(cur_phase));
            return false;
        }
    }

    void ForgetPeer(NodeId peer_id) EXCLUSIVE_LOCKS_REQUIRED(!m_txreconciliation_mutex)
    {
        AssertLockNotHeld(m_txreconciliation_mutex);
        LOCK(m_txreconciliation_mutex);
        const auto peer = m_states.find(peer_id);
        if (peer == m_states.end()) return;

        const auto registered = std::get_if<TxReconciliationState>(&peer->second);
        if (registered) {
            if (registered->m_we_initiate) {
                m_queue.erase(std::remove(m_queue.begin(), m_queue.end(), peer_id), m_queue.end());
            } else {
                Assert(m_inbounds_count > 0);
                --m_inbounds_count;
            }
        }

        m_states.erase(peer);
        LogPrintLevel(BCLog::TXRECONCILIATION, BCLog::Level::Debug, "Forget txreconciliation state of peer=%d\n", peer_id);
    }

    /**
     * For calls within this class use GetRegisteredPeerState instead.
     */
    bool IsPeerRegistered(NodeId peer_id) const EXCLUSIVE_LOCKS_REQUIRED(!m_txreconciliation_mutex)
    {
        AssertLockNotHeld(m_txreconciliation_mutex);
        LOCK(m_txreconciliation_mutex);
        auto recon_state = m_states.find(peer_id);
        return (recon_state != m_states.end() &&
                std::holds_alternative<TxReconciliationState>(recon_state->second));
    }

    std::vector<NodeId> GetFanoutTargets(const Wtxid& wtxid, size_t inbounds_fanout_tx_relay, size_t outbounds_fanout_tx_relay) const EXCLUSIVE_LOCKS_REQUIRED(!m_txreconciliation_mutex)
    {
        AssertLockNotHeld(m_txreconciliation_mutex);
        LOCK(m_txreconciliation_mutex);

        // We decide whether a particular peer is a low-fanout flood target differently based on its connection direction:
        // - for outbounds we have a fixed number of flood destinations.
        // - for inbounds we use a fraction of all inbound peers supporting tx relay.
        size_t outbounds_target_size = 0;
        if (OUTBOUND_FANOUT_DESTINATIONS > outbounds_fanout_tx_relay) {
            outbounds_target_size = OUTBOUND_FANOUT_DESTINATIONS - outbounds_fanout_tx_relay;
        }

        // Since we use the fraction for inbound peers, we first need to compute the total number of inbound targets.
        const double inbound_targets = (inbounds_fanout_tx_relay + m_inbounds_count) * INBOUND_FANOUT_DESTINATIONS_FRACTION;
        double n = std::max(inbound_targets - inbounds_fanout_tx_relay, 0.0);

        // Being this a fraction, we need to round it either up or down. We do this deterministically at random based on the
        // transaction we are picking the peers for.
        CSipHasher deterministic_randomizer_in{m_deterministic_randomizer};
        deterministic_randomizer_in.Write(wtxid.ToUint256());
        CSipHasher deterministic_randomizer_out{deterministic_randomizer_in};
        const size_t inbounds_target_size = ((deterministic_randomizer_in.Finalize() & 0xFFFFFFFF) + uint64_t(n * 0x100000000)) >> 32;

        // Pick all reconciliation registered peers and assign them a deterministically random value based on their peer id
        // Also, split peers in inbounds/outbounds
        std::vector<std::pair<uint64_t, NodeId>> sorted_inbounds, sorted_outbounds;
        sorted_inbounds.reserve(m_inbounds_count);
        Assume(m_states.size() >= m_inbounds_count);
        sorted_outbounds.reserve(m_states.size() - m_inbounds_count);
        for (const auto& [node_id, op_peer_state]: m_states) {
            const auto peer_state = std::get_if<TxReconciliationState>(&op_peer_state);
            if (peer_state) {
                if (peer_state->m_we_initiate) {
                    uint64_t hash_key = CSipHasher(deterministic_randomizer_out).Write(node_id).Finalize();
                    sorted_outbounds.emplace_back(hash_key, node_id);
                } else {
                    uint64_t hash_key = CSipHasher(deterministic_randomizer_in).Write(node_id).Finalize();
                    sorted_inbounds.emplace_back(hash_key, node_id);
                }

            }
        }

        // Sort the peers based on their assigned random value, extract the node_ids and trim the collections to size
        std::vector<NodeId> in_fanout_targets;
        if (inbounds_target_size >= 1) {
            std::sort(sorted_inbounds.begin(), sorted_inbounds.end());
            for_each(sorted_inbounds.begin(), sorted_inbounds.end(),
                    [&in_fanout_targets](auto& keyed_peer) { in_fanout_targets.push_back(keyed_peer.second); });
            in_fanout_targets.resize(inbounds_target_size);
        }
        std::vector<NodeId> out_fanout_targets;
        if (outbounds_target_size >= 1) {
            std::sort(sorted_outbounds.begin(), sorted_outbounds.end());
            for_each(sorted_outbounds.begin(), sorted_outbounds.end(),
                    [&out_fanout_targets](auto& keyed_peer) { out_fanout_targets.push_back(keyed_peer.second); });
            out_fanout_targets.resize(outbounds_target_size);
        }

        // Merge both vectors and return
        in_fanout_targets.insert(in_fanout_targets.end(), out_fanout_targets.begin(), out_fanout_targets.end());

        return in_fanout_targets;
    }

    bool ShouldFanoutTo(NodeId peer_id, std::vector<NodeId> &fanout_targets) EXCLUSIVE_LOCKS_REQUIRED(!m_txreconciliation_mutex)
    {
        AssertLockNotHeld(m_txreconciliation_mutex);
        LOCK(m_txreconciliation_mutex);
        auto peer_state = GetRegisteredPeerState(peer_id);
        if (!peer_state) return true;

        return std::find(fanout_targets.begin(), fanout_targets.end(), peer_id) != fanout_targets.end();
    }

    std::vector<NodeId> SortPeersByFewestParents(std::vector<Wtxid> parents) EXCLUSIVE_LOCKS_REQUIRED(!m_txreconciliation_mutex)
    {
        AssertLockNotHeld(m_txreconciliation_mutex);
        LOCK(m_txreconciliation_mutex);

        std::vector<std::pair<uint16_t, NodeId>> parents_by_peer{};
        for (const auto &[peer_id, _]: m_states) {
            if (GetRegisteredPeerState(peer_id)) {
                parents_by_peer.emplace_back(0, peer_id);
            }
        }

        for (auto &[parent_count, peer_id]: parents_by_peer) {
            auto state = std::get<TxReconciliationState>(m_states.find(peer_id)->second);
            for (const auto& wtxid: parents) {
                if (state.ContainsTx(wtxid, /*include_delayed=*/true)) {
                    ++parent_count;
                }
            }
        }

        std::sort(parents_by_peer.begin(), parents_by_peer.end());
        std::vector<NodeId> sorted_peers;
        sorted_peers.reserve(parents_by_peer.size());
        for (const auto &[_, node_id]: parents_by_peer) {
            sorted_peers.emplace_back(node_id);
        }

        return sorted_peers;
    }
};

AddToSetResult::AddToSetResult(bool succeeded, std::optional<Wtxid> conflict)
{
    m_succeeded = succeeded;
    m_conflict = conflict;
}

AddToSetResult AddToSetResult::Succeeded()
{
    return AddToSetResult(true, std::nullopt);
}

AddToSetResult AddToSetResult::Failed()
{
    return AddToSetResult(false, std::nullopt);
}

AddToSetResult AddToSetResult::Collision(Wtxid wtxid)
{
    return AddToSetResult(false, std::make_optional(wtxid));
}

TxReconciliationTracker::TxReconciliationTracker(uint32_t recon_version, CSipHasher hasher) : m_impl{std::make_unique<TxReconciliationTracker::Impl>(recon_version, hasher)} {}

TxReconciliationTracker::~TxReconciliationTracker() = default;

uint64_t TxReconciliationTracker::PreRegisterPeer(NodeId peer_id)
{
    const uint64_t local_salt{FastRandomContext().rand64()};
    return m_impl->PreRegisterPeer(peer_id, local_salt);
}

void TxReconciliationTracker::PreRegisterPeerWithSalt(NodeId peer_id, uint64_t local_salt)
{
    m_impl->PreRegisterPeer(peer_id, local_salt);
}

ReconciliationRegisterResult TxReconciliationTracker::RegisterPeer(NodeId peer_id, bool is_peer_inbound,
                                                          uint32_t peer_recon_version, uint64_t remote_salt)
{
    return m_impl->RegisterPeer(peer_id, is_peer_inbound, peer_recon_version, remote_salt);
}

AddToSetResult TxReconciliationTracker::AddToSet(NodeId peer_id, const Wtxid& wtxid)
{
    return m_impl->AddToSet(peer_id, wtxid);
}

bool TxReconciliationTracker::ReadyDelayedTransactions(NodeId peer_id)
{
    return m_impl->ReadyDelayedTransactions(peer_id);
}

bool TxReconciliationTracker::IsTransactionInSet(NodeId peer_id, const Wtxid& wtxid, bool include_delayed)
{
    return m_impl->IsTransactionInSet(peer_id, wtxid, include_delayed);
}

bool TxReconciliationTracker::TryRemovingFromSet(NodeId peer_id, const Wtxid& wtxid)
{
    return m_impl->TryRemovingFromSet(peer_id, wtxid);
}

bool TxReconciliationTracker::IsPeerNextToReconcileWith(NodeId peer_id, std::chrono::microseconds now)
{
    return m_impl->IsPeerNextToReconcileWith(peer_id, now);
}

std::optional<std::pair<uint16_t, uint16_t>> TxReconciliationTracker::InitiateReconciliationRequest(NodeId peer_id)
{
    return m_impl->InitiateReconciliationRequest(peer_id);
}

void TxReconciliationTracker::HandleReconciliationRequest(NodeId peer_id, uint16_t peer_recon_set_size, uint16_t peer_q)
{
    m_impl->HandleReconciliationRequest(peer_id, peer_recon_set_size, peer_q);
}

bool TxReconciliationTracker::RespondToReconciliationRequest(NodeId peer_id, std::vector<uint8_t>& skdata)
{
    return m_impl->RespondToReconciliationRequest(peer_id, skdata);
}

bool TxReconciliationTracker::HandleSketch(NodeId peer_id, const std::vector<uint8_t>& skdata,
    std::vector<uint32_t>& txs_to_request, std::vector<uint256>& txs_to_announce, std::optional<bool>& result)
{
    return m_impl->HandleSketch(peer_id, skdata, txs_to_request, txs_to_announce, result);
}

void TxReconciliationTracker::ForgetPeer(NodeId peer_id)
{
    m_impl->ForgetPeer(peer_id);
}

bool TxReconciliationTracker::IsPeerRegistered(NodeId peer_id) const
{
    return m_impl->IsPeerRegistered(peer_id);
}

std::vector<NodeId> TxReconciliationTracker::GetFanoutTargets(const Wtxid& wtxid, size_t inbounds_fanout_tx_relay, size_t outbounds_fanout_tx_relay)
{
    return m_impl->GetFanoutTargets(wtxid, inbounds_fanout_tx_relay, outbounds_fanout_tx_relay);
}

bool TxReconciliationTracker::ShouldFanoutTo(NodeId peer_id, std::vector<NodeId> &fanout_targets)
{
    return m_impl->ShouldFanoutTo(peer_id, fanout_targets);
}

std::vector<NodeId> TxReconciliationTracker::SortPeersByFewestParents(std::vector<Wtxid> parents)
{
    return m_impl->SortPeersByFewestParents(parents);
}
