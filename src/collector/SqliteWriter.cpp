#include "collector/SqliteWriter.h"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <cassert>
#include <cstring>

namespace angelia::collector {

namespace {

constexpr const char* kSchema = R"SQL(
CREATE TABLE IF NOT EXISTS events (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_100ns   INTEGER NOT NULL,
    pid               INTEGER NOT NULL,
    tid               INTEGER NOT NULL,
    kind              INTEGER NOT NULL,
    event_id          INTEGER NOT NULL,
    opcode            INTEGER NOT NULL,
    level             INTEGER NOT NULL,
    name              TEXT,          -- primary path / image / key name
    attrs             TEXT,          -- per-kind JSON extras (nullable)
    truncated_name    INTEGER NOT NULL DEFAULT 0,
    truncated_attrs   INTEGER NOT NULL DEFAULT 0,
    provider          INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_events_pid_ts   ON events(pid, timestamp_100ns);
CREATE INDEX IF NOT EXISTS ix_events_ts       ON events(timestamp_100ns);
CREATE INDEX IF NOT EXISTS ix_events_kind_ts  ON events(kind, timestamp_100ns);
CREATE INDEX IF NOT EXISTS ix_events_pid_kind ON events(pid, kind, timestamp_100ns);
)SQL";

constexpr const char* kInsert = R"SQL(
INSERT INTO events (
    timestamp_100ns, pid, tid, kind, event_id, opcode, level,
    name, attrs, truncated_name, truncated_attrs, provider)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?);
)SQL";

}  // namespace

namespace {
std::size_t round_up_pow2(std::size_t n) noexcept {
    std::size_t p = 1;
    while (p < n) p <<= 1;
    return p;
}
}  // namespace

SqliteWriter::SqliteWriter(const std::filesystem::path& db_path, WriterConfig cfg)
    : path_(db_path),
      cfg_([&] { cfg.queue_capacity = round_up_pow2(cfg.queue_capacity); return cfg; }()),
      pool_(cfg_.queue_capacity),
      queue_(cfg_.queue_capacity) {}

SqliteWriter::~SqliteWriter() { stop(); }

void SqliteWriter::start() {
    db_.open(path_);
    common::configure_for_ingest(db_);
    db_.exec(kSchema);
    ins_    = db_.prepare(kInsert);
    begin_  = db_.prepare("BEGIN IMMEDIATE;");
    commit_ = db_.prepare("COMMIT;");
    thread_ = std::thread([this] { run(); });
}

void SqliteWriter::stop() {
    if (!thread_.joinable()) return;
    stop_.store(true, std::memory_order_release);
    thread_.join();
    ins_ = common::Statement{};
    begin_ = common::Statement{};
    commit_ = common::Statement{};
    db_.close();
}

void SqliteWriter::run() {
    using clock = std::chrono::steady_clock;
    std::vector<EventRecord*> batch;
    batch.reserve(cfg_.batch_events);

    auto last_flush = clock::now();

    while (true) {
        EventRecord* rec = nullptr;
        while (batch.size() < cfg_.batch_events && queue_.try_pop(rec)) {
            batch.push_back(rec);
        }

        const auto depth = queue_.size_approx();
        uint64_t prev = metrics_.queue_depth_max.load(std::memory_order_relaxed);
        while (depth > prev &&
               !metrics_.queue_depth_max.compare_exchange_weak(prev, depth,
                       std::memory_order_relaxed)) {}

        const auto now = clock::now();
        const bool time_flush =
            std::chrono::duration_cast<std::chrono::microseconds>(now - last_flush)
                > cfg_.batch_max_us;
        const bool size_flush = batch.size() >= cfg_.batch_events;

        if (!batch.empty() && (size_flush || time_flush)) {
            commit_batch(batch.data(), batch.size());
            for (auto* r : batch) pool_.release(r);
            batch.clear();
            last_flush = clock::now();
        }

        metrics_.writer_iterations.fetch_add(1, std::memory_order_relaxed);

        if (batch.empty() && queue_.size_approx() == 0) {
            if (stop_.load(std::memory_order_acquire)) break;
            std::this_thread::sleep_for(std::chrono::microseconds{200});
        } else if (!size_flush && !time_flush) {
            // Have some work but not enough — yield a hair to let producers fill.
            std::this_thread::yield();
        }
    }

    // Drain any remainder.
    std::vector<EventRecord*> drain;
    drain.reserve(cfg_.batch_events);
    EventRecord* rec = nullptr;
    while (queue_.try_pop(rec)) {
        drain.push_back(rec);
        if (drain.size() >= cfg_.batch_events) {
            commit_batch(drain.data(), drain.size());
            for (auto* r : drain) pool_.release(r);
            drain.clear();
        }
    }
    if (!drain.empty()) {
        commit_batch(drain.data(), drain.size());
        for (auto* r : drain) pool_.release(r);
    }
}

void SqliteWriter::commit_batch(EventRecord* const* recs, std::size_t n) {
    using clock = std::chrono::steady_clock;
    const auto t0 = clock::now();

    // synchronous=NORMAL + WAL collapses per-row fsyncs into one per COMMIT.
    begin_.step();
    begin_.reset();

    for (std::size_t i = 0; i < n; ++i) {
        const EventRecord& r = *recs[i];
        ins_.bind_int64(1, static_cast<int64_t>(r.timestamp_100ns));
        ins_.bind_int64(2, static_cast<int64_t>(r.pid));
        ins_.bind_int64(3, static_cast<int64_t>(r.tid));
        ins_.bind_int  (4, static_cast<int32_t>(r.kind));
        ins_.bind_int  (5, static_cast<int32_t>(r.event_id));
        ins_.bind_int  (6, static_cast<int32_t>(r.opcode));
        ins_.bind_int  (7, static_cast<int32_t>(r.level));
        if (r.name_len)    ins_.bind_text(8, r.name_view());       else ins_.bind_null(8);
        if (r.payload_len) ins_.bind_text(9, std::string_view{
                                reinterpret_cast<const char*>(r.payload.data()),
                                r.payload_len});
        else               ins_.bind_null(9);
        ins_.bind_int(10, r.truncated_name);
        ins_.bind_int(11, r.truncated_payload);
        ins_.bind_int(12, r.provider);
        (void)ins_.step();
        ins_.reset();
    }

    commit_.step();
    commit_.reset();

    metrics_.events_committed.fetch_add(n, std::memory_order_relaxed);
    metrics_.transactions.fetch_add(1, std::memory_order_relaxed);

    const auto us = std::chrono::duration_cast<std::chrono::microseconds>(clock::now() - t0);
    record_commit_latency(us);
}

void SqliteWriter::finalise_latency_quantiles() {
    const std::size_t n = std::min<std::size_t>(latency_ring_pos_, kLatencySamples);
    if (n == 0) return;
    std::vector<uint32_t> tmp(latency_ring_, latency_ring_ + n);
    std::sort(tmp.begin(), tmp.end());
    metrics_.commit_latency_p50_est_us.store(tmp[n / 2], std::memory_order_relaxed);
    metrics_.commit_latency_p99_est_us.store(
        tmp[std::min<std::size_t>(n - 1, (n * 99) / 100)],
        std::memory_order_relaxed);
}

void SqliteWriter::record_commit_latency(std::chrono::microseconds us) {
    const auto v = static_cast<uint64_t>(us.count());
    metrics_.commit_latency_sum_us.fetch_add(v, std::memory_order_relaxed);
    uint64_t mx = metrics_.commit_latency_max_us.load(std::memory_order_relaxed);
    while (v > mx && !metrics_.commit_latency_max_us.compare_exchange_weak(
                             mx, v, std::memory_order_relaxed)) {}
    latency_ring_[latency_ring_pos_++ % kLatencySamples] = static_cast<uint32_t>(std::min<uint64_t>(v, UINT32_MAX));
    if (latency_ring_pos_ % 256 == 0) {
        // Cheap approximate p50/p99 over the ring.
        std::size_t n = std::min<std::size_t>(latency_ring_pos_, kLatencySamples);
        std::vector<uint32_t> tmp(latency_ring_, latency_ring_ + n);
        std::sort(tmp.begin(), tmp.end());
        metrics_.commit_latency_p50_est_us.store(tmp[n / 2], std::memory_order_relaxed);
        metrics_.commit_latency_p99_est_us.store(tmp[std::min<std::size_t>(n - 1, (n * 99) / 100)],
                                                 std::memory_order_relaxed);
    }
}

}  // namespace angelia::collector
