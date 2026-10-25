#include <gtest/gtest.h>

#include <filesystem>
#include <string>

#include <sqlite3.h>

#include "collector/EventRecord.h"
#include "riskscore/BehavioralScorer.h"

using angelia::collector::EventKind;
using namespace angelia::riskscore;

namespace {

// Small SQLite fixture that mimics the shape of collector.db so we can
// exercise the behavioural scorer without spinning up the ETW pipeline.
class TimelineFixture : public ::testing::Test {
protected:
    std::filesystem::path path;
    sqlite3* db = nullptr;

    void SetUp() override {
        path = std::filesystem::temp_directory_path() /
            (std::string("angelia_behav_test_") +
             ::testing::UnitTest::GetInstance()->current_test_info()->name() + ".db");
        std::error_code ec; std::filesystem::remove(path, ec);
        const auto p8 = path.u8string();
        ASSERT_EQ(sqlite3_open(reinterpret_cast<const char*>(p8.c_str()), &db), SQLITE_OK)
            << "cannot open fixture DB";
        const char* schema =
            "CREATE TABLE events ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "timestamp_100ns INTEGER NOT NULL, "
            "pid INTEGER NOT NULL, tid INTEGER NOT NULL, kind INTEGER NOT NULL, "
            "event_id INTEGER NOT NULL DEFAULT 0, opcode INTEGER NOT NULL DEFAULT 0, "
            "level INTEGER NOT NULL DEFAULT 4, name TEXT, attrs TEXT, "
            "truncated_name INTEGER NOT NULL DEFAULT 0, "
            "truncated_attrs INTEGER NOT NULL DEFAULT 0);";
        ASSERT_EQ(sqlite3_exec(db, schema, nullptr, nullptr, nullptr), SQLITE_OK);
    }
    void TearDown() override {
        if (db) sqlite3_close_v2(db);
        std::error_code ec; std::filesystem::remove(path, ec);
    }
    void insert(uint64_t ts, uint32_t pid, EventKind k, const char* name = nullptr) {
        sqlite3_stmt* s = nullptr;
        ASSERT_EQ(sqlite3_prepare_v2(db,
            "INSERT INTO events(timestamp_100ns,pid,tid,kind,name) VALUES (?,?,?,?,?)",
            -1, &s, nullptr), SQLITE_OK);
        sqlite3_bind_int64(s, 1, static_cast<sqlite3_int64>(ts));
        sqlite3_bind_int64(s, 2, static_cast<sqlite3_int64>(pid));
        sqlite3_bind_int64(s, 3, 1);
        sqlite3_bind_int  (s, 4, static_cast<int>(k));
        if (name) sqlite3_bind_text(s, 5, name, -1, SQLITE_TRANSIENT);
        else      sqlite3_bind_null(s, 5);
        ASSERT_EQ(sqlite3_step(s), SQLITE_DONE);
        sqlite3_finalize(s);
    }
};

TEST_F(TimelineFixture, BenignPidGetsZeroScore) {
    // A "benign" PID: just image loads from System32 and a few file reads.
    for (uint64_t t = 0; t < 20; ++t)
        insert(t, 1000, EventKind::ImageLoad, "C:\\Windows\\System32\\kernel32.dll");
    for (uint64_t t = 20; t < 40; ++t)
        insert(t, 1000, EventKind::FileRead, "C:\\Windows\\System32\\config\\SOFTWARE");

    auto r = score_timeline(path);
    ASSERT_TRUE(r.ok) << r.error;
    ASSERT_EQ(r.distinct_pids, 1u);
    EXPECT_EQ(r.pids.front().pid, 1000u);
    EXPECT_DOUBLE_EQ(r.pids.front().score, 0.0);
}

TEST_F(TimelineFixture, MalwareShapedPidFlagsMultipleRules) {
    const uint32_t pid = 4242;
    insert(1, pid, EventKind::ProcessStart, "C:\\Users\\bob\\Downloads\\update.exe");
    insert(2, pid, EventKind::ImageLoad,    "C:\\Users\\bob\\AppData\\Local\\Temp\\payload.dll");
    insert(3, pid, EventKind::ImageLoad,    "C:\\Users\\bob\\AppData\\Roaming\\a.dll");
    // 60 distinct file writes = ransomware fanout indicator
    for (int i = 0; i < 60; ++i) {
        insert(10 + i, pid, EventKind::FileWrite,
               ("C:\\Users\\bob\\Docs\\file" + std::to_string(i) + ".dat").c_str());
    }
    // Persistence: write to a Run key
    insert(100, pid, EventKind::RegistrySetValue,
           "\\REGISTRY\\MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\updater");

    auto r = score_timeline(path);
    ASSERT_TRUE(r.ok) << r.error;
    ASSERT_EQ(r.distinct_pids, 1u);
    const auto& p = r.pids.front();
    EXPECT_EQ(p.pid, pid);
    EXPECT_GT(p.score, 0.9);   // saturates high — reg-run + user-writable-dll + fanout + installer
    // Confirm each expected rule appears in features:
    auto has = [&](std::string_view name) {
        for (const auto& f : p.features) if (f.name == name) return true;
        return false;
    };
    EXPECT_TRUE(has("reg-run-persistence"));
    EXPECT_TRUE(has("dll-from-user-writable"));
    EXPECT_TRUE(has("high-fanout-file-write"));
    EXPECT_TRUE(has("installation-flow"));
}

TEST_F(TimelineFixture, SeparatesBenignFromMalwareShape) {
    // Both processes in same DB so we can confirm the *separation* the
    // plan asks us to measure before reaching for a Markov model.
    const uint32_t benign = 1001;
    const uint32_t malic  = 6666;
    for (uint64_t t = 0; t < 30; ++t)
        insert(t, benign, EventKind::FileRead, "C:\\Windows\\System32\\ntdll.dll");
    insert(1, malic, EventKind::ProcessStart, "C:\\Users\\x\\Downloads\\bad.exe");
    insert(2, malic, EventKind::ImageLoad,   "C:\\Users\\x\\AppData\\Local\\Temp\\bad.dll");
    for (int i = 0; i < 80; ++i)
        insert(10 + i, malic, EventKind::FileWrite,
               ("C:\\U\\a" + std::to_string(i)).c_str());
    insert(200, malic, EventKind::RegistrySetValue,
           "\\Registry\\User\\...\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\z");

    auto r = score_timeline(path);
    ASSERT_TRUE(r.ok) << r.error;
    ASSERT_EQ(r.distinct_pids, 2u);
    // Ranked by score desc, malicious should be first.
    EXPECT_EQ(r.pids[0].pid, malic);
    EXPECT_EQ(r.pids[1].pid, benign);
    EXPECT_GT(r.pids[0].score - r.pids[1].score, 0.7);   // meaningful separation
}

}  // namespace
