#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <thread>
#include <vector>

#include <sqlite3.h>

#include "collector/EventRecord.h"
#include "collector/SqliteWriter.h"

namespace {

TEST(SqliteWriter, EndToEndSmallLoad) {
    namespace fs = std::filesystem;
    fs::path db = fs::temp_directory_path() / "angelia_sqlite_writer_test.db";
    std::error_code ec; fs::remove(db, ec);

    angelia::collector::WriterConfig cfg;
    cfg.batch_events   = 128;
    cfg.queue_capacity = 4096;
    angelia::collector::SqliteWriter w(db, cfg);
    w.start();

    constexpr uint64_t kEvents = 10'000;
    for (uint64_t i = 0; i < kEvents; ++i) {
        auto* rec = w.pool().try_acquire();
        while (!rec) { std::this_thread::yield(); rec = w.pool().try_acquire(); }
        rec->timestamp_100ns = 100 + i;
        rec->pid = 42;
        rec->tid = 7;
        rec->event_id = 1;
        rec->kind = angelia::collector::EventKind::Synthetic;
        rec->set_name("proc.exe");
        while (!w.push(rec)) std::this_thread::yield();
    }
    while (w.metrics().events_committed.load() < kEvents) {
        std::this_thread::sleep_for(std::chrono::milliseconds{5});
    }
    w.stop();

    sqlite3* raw = nullptr;
    const auto db_u8 = db.u8string();
    ASSERT_EQ(sqlite3_open(reinterpret_cast<const char*>(db_u8.c_str()), &raw), SQLITE_OK);
    sqlite3_stmt* s = nullptr;
    ASSERT_EQ(sqlite3_prepare_v2(raw, "SELECT COUNT(*), MIN(timestamp_100ns), MAX(timestamp_100ns) FROM events",
                                 -1, &s, nullptr), SQLITE_OK);
    ASSERT_EQ(sqlite3_step(s), SQLITE_ROW);
    EXPECT_EQ(sqlite3_column_int64(s, 0), static_cast<sqlite3_int64>(kEvents));
    EXPECT_EQ(sqlite3_column_int64(s, 1), 100);
    EXPECT_EQ(sqlite3_column_int64(s, 2), static_cast<sqlite3_int64>(100 + kEvents - 1));
    sqlite3_finalize(s);
    sqlite3_close(raw);
    fs::remove(db, ec);
    fs::remove(fs::path{db}.replace_extension(".db-wal"), ec);
    fs::remove(fs::path{db}.replace_extension(".db-shm"), ec);
}

}  // namespace
