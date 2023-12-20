// Copyright (c) 2020-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>

#include <net.h>
#include <node/txreconciliation.h>


/* Benchmarks */

static void ShouldFanoutTo(benchmark::Bench& bench)
{
    TxReconciliationTracker tracker(1);
    // Register 120 inbound peers
    int num_peers{120};
    for(NodeId peer=0; peer < num_peers; peer++) {
        tracker.PreRegisterPeer(peer);
        tracker.RegisterPeer(peer, /*is_peer_inbound=*/true, 1, 1);
    }
    FastRandomContext rc{/*fDeterministic=*/true};
    CSipHasher hasher(0x0706050403020100ULL, 0x0F0E0D0C0B0A0908ULL);

    std::vector<Wtxid> txs;
    for (size_t i = 0; i < 1000; i++) {
        txs.push_back(Wtxid::FromUint256(rc.rand256()));
    }

    bench.run([&] {
        size_t rand_i = rand() % txs.size();
        for (NodeId peer = 0; peer < num_peers; ++peer) {
            tracker.ShouldFanoutTo(txs[rand_i], CSipHasher(hasher), peer,/*inbounds_nonrcncl_tx_relay=*/0, /*outbounds_nonrcncl_tx_relay=*/0);
        }
    });
}

BENCHMARK(ShouldFanoutTo, benchmark::PriorityLevel::HIGH);
