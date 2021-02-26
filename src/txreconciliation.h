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
 * Used to track reconciliations across all peers.
 */
class TxReconciliationTracker {
    // Avoid littering this header file with implementation details.
    class Impl;
    const std::unique_ptr<Impl> m_impl;

    public:

    explicit TxReconciliationTracker();
    ~TxReconciliationTracker();

    /**
     * Generates (and stores) a peer-specific salt which will be used for reconciliations.
     * Returns the following values which will be used to invite a peer to reconcile:
     * - whether we want to initiate reconciliations (request sketches)
     * - whether we agree to respond to reconciliations (send our sketches)
     * - reconciliation version (currently, 1)
     * - peer-specific salt
     */
    std::tuple<bool, bool, uint32_t, uint64_t> SuggestReconciling(const NodeId peer_id, bool inbound);

    /**
     * Start tracking state of reconciliation with the peer, and add it to the reconciliation
     * queue if it is an outbound connection. Decide whether we should flood certain transactions
     * to the peer based on the number of existing outbound flood connections.
     * Should be called only after SuggestReconciling for the same peer and only once.
     * Returns false if a peer seems to violate the protocol rules.
     */
    bool EnableReconciliationSupport(const NodeId peer_id, bool inbound,
        bool recon_requestor, bool recon_responder, uint32_t recon_version, uint64_t remote_salt,
        size_t outbound_flooders);

    /**
     * Per BIP-330, we may want to flood certain transactions to a subset of peers with whom we
     * reconcile.
     */
    std::optional<bool> IsPeerChosenForFlooding(const NodeId peer_id) const;
};

#endif // BITCOIN_TXRECONCILIATION_H
