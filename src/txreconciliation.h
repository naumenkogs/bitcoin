// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TXRECONCILIATION_H
#define BITCOIN_TXRECONCILIATION_H

#include <net.h>
#include <sync.h>

#include <tuple>
#include <unordered_map>

/**
 * Transaction reconciliation is a way for nodes to efficiently announce transactions.
 * This object keeps track of all reconciliation-related communications with the peers.
 * The high-level protocol is:
 * 0. Reconciliation protocol handshake.
 * 1. Once we receive a new transaction, add it to the set instead of announcing immediately
 * 2. When the time comes, a reconciliation initiator requests a sketch from the peer, where a sketch
 *    is a compressed representation of their set
 * 3. Once the initiator received a sketch from the peer, the initiator computes a local sketch,
 *    and combines the two skethes to find the difference in *sets*.
 * 4. Now the initiator knows full symmetrical difference and can request what the initiator is
 *    missing and announce to the peer what the peer is missing. For the former, an extra round is
 *    required because the initiator knows only short IDs of those transactions.
 * 5. Sometimes reconciliation fails if the difference is larger than the parties estimated,
 *    then there is one sketch extension round, in which the initiator requests for extra data.
 * 6. If extension succeeds, go to step 4.
 * 7. If extension fails, the initiator notifies the peer
 */
class TxReconciliationTracker {
    // Avoid littering this header file with implementation details.
    class Impl;
    const std::unique_ptr<Impl> m_impl;

    public:

    explicit TxReconciliationTracker();
    ~TxReconciliationTracker();

    /**
     * Step 0. Generate and pass reconciliation parameters to be sent along with the suggestion
     * to announce transactions via reconciliations.
     * Generates (and stores) a peer-specific salt which will be used for reconciliations.
     * Reconciliation roles are based on inbound/outbound role in the connection.
     * Returns the following values which will be used to invite a peer to reconcile:
     * - whether we want to initiate reconciliation requests (ask for sketches)
     * - whether we agree to respond to reconciliation requests (send our sketches)
     * - reconciliation protocol version
     * - salt used for short ID computation required for reconciliation
     * A peer can't be registered for future reconciliations without this call.
     */
    std::tuple<bool, bool, uint32_t, uint64_t> SuggestReconciling(NodeId peer_id, bool inbound);

    /**
     * Step 0. Once the peer agreed to reconcile with us, generate the data structures required
     * to track transactions we are going to announce and reconciliation-related parameters.
     * At this point, we decide whether we want to also flood certain transactions to the peer
     * along with reconciliations.
     * Add the peer to the queue if we are going to be the reconciliation initiator.
     * Should be called only after SuggestReconciling for the same peer and only once.
     * Returns false if a peer seems to violate the protocol rules.
     */
    bool EnableReconciliationSupport(NodeId peer_id, bool inbound,
        bool recon_requestor, bool recon_responder, uint32_t recon_version, uint64_t remote_salt,
        size_t outbound_flooders);

    /**
     * Step 1. Add new transactions we want to announce to the peer to the local reconciliation set
     * of the peer, so that those transactions will be reconciled later.
     */
    void StoreTxsToAnnounce(NodeId peer_id, const std::vector<uint256>& txs_to_reconcile);

    // Helpers

    /**
     * Removes reconciliation-related state of the peer. After this, we won't be able to reconcile
     * with the peer unless it's registered again (see Step 0).
     */
    void RemovePeer(NodeId peer_id);

    /**
     * Check if a peer is registered to reconcile with us.
     */
    bool IsPeerRegistered(NodeId peer_id) const;

    /**
     * Per BIP-330, we may want to flood certain transactions to a subset of peers with whom we
     * reconcile.
     * If the peer was not previously registered for reconciliations, returns nullopt.
     */
    std::optional<bool> IsPeerChosenForFlooding(NodeId peer_id) const;

    /**
     * Tells whether a given peer might respond to our reconciliation requests.
     * If the peer was not previously registered for reconciliations, returns nullopt.
     */
    std::optional<bool> IsPeerResponder(NodeId peer_id) const;

    /**
     * Returns the size of the reconciliation set we have locally for the given peer.
     * If the peer was not previously registered for reconciliations, returns nullopt.
     */
    std::optional<size_t> GetPeerSetSize(NodeId peer_id) const;
};

#endif // BITCOIN_TXRECONCILIATION_H