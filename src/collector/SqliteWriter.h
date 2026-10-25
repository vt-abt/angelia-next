#pragma once

// Single-threaded SQLite writer. Producers push completed EventRecord*
// slots into the queue; this thread drains, inserts in prepared-statement
// batches wrapped in explicit transactions, then returns each slot to the
// pool. Metrics are read-live from any thread.

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <thread>

#include "collector/EventRecord.h"
#include "common/MpmcQueue.h"
#include "common/ObjectPool.h"
#include "common/Sqlite.h"

namespace angelia::collector {

struct WriterConfig {
    std::size_t                batch_events = 1024;
    std::chrono::microseconds  batch_max_us = std::chrono::microseconds{50'000};
    std::size_t                queue_capacity = 1u << 17;   // 131072 slots
};

struct WriterMetrics {
    std::atomic<uint64_t> events_committed{0};
    std::atomic<uint64_t> transactions{0};
    std::atomic<uint64_t> pool_drops{0};       // no slot available in the pool
    std::atomic<uint64_t> queue_drops{0};      // queue was full
    std::atomic<uint64_t> writer_iterations{0};
    std::atomic<uint64_t> queue_depth_max{0};
    std::atomic<uint64_t> commit_latency_max_us{0};
    std::atomic<uint64_t> commit_latency_sum_us{0};   // for mean
    std::atomic<uint64_t> commit_latency_p50_est_us{0};
    std::atomic<uint64_t> commit_latency_p99_est_us{0};
};

class SqliteWriter {
public:
    SqliteWriter(const std::filesystem::path& db_path, WriterConfig cfg);
    ~SqliteWriter();

    SqliteWriter(const SqliteWriter&)            = delete;
    SqliteWriter& operator=(const SqliteWriter&) = delete;

    void start();
    void stop();

    // Called by producers. Returns false if the queue is full — in that
    // case the caller must release the slot back to the pool.
    bool push(EventRecord* rec) noexcept {
        const bool ok = queue_.try_push(rec);
        if (!ok) metrics_.queue_drops.fetch_add(1, std::memory_order_relaxed);
        return ok;
    }

    // Pool the collector borrows from. Owned by the writer so its lifetime
    // outlives every producer thread.
    common::ObjectPool<EventRecord>& pool() noexcept { return pool_; }

    const WriterMetrics& metrics() const noexcept { return metrics_; }
    WriterMetrics&       metrics() noexcept       { return metrics_; }

    // Approximate current queue depth — for the depth-histogram sampler.
    std::size_t queue_depth() const noexcept { return queue_.size_approx(); }

    // Force-compute the p50/p99 latency estimates from whatever samples
    // are currently in the ring. Meant to be called once after stop() so
    // short runs (< 256 commits) still get non-zero quantile readouts.
    void finalise_latency_quantiles();

private:
    void run();
    void commit_batch(EventRecord* const* recs, std::size_t n);
    void record_commit_latency(std::chrono::microseconds us);

    std::filesystem::path            path_;
    WriterConfig                     cfg_;
    common::ObjectPool<EventRecord>  pool_;
    common::MpmcQueue<EventRecord*>  queue_;
    WriterMetrics                    metrics_;

    common::Database   db_;
    common::Statement  ins_;
    common::Statement  begin_;
    common::Statement  commit_;

    std::thread            thread_;
    std::atomic<bool>      stop_{false};

    // Reservoir-ish sampled latencies — kept small so we can return
    // approximate quantiles without a stats library.
    static constexpr std::size_t kLatencySamples = 4096;
    uint32_t latency_ring_[kLatencySamples]{};
    std::size_t latency_ring_pos_ = 0;
};

}  // namespace angelia::collector
