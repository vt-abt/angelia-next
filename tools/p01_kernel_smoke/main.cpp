// Stage 1 smoke test.
//
// Starts an NT-Kernel-Logger session with Process / ImageLoad / File-IO /
// Registry providers, runs for --duration seconds, then reports what
// landed: throughput, drops, queue-depth max, per-kind breakdown, top
// processes by event count. Requires an elevated shell — creating a
// system logger session needs SeSecurityPrivilege /
// EVENT_TRACE_SYSTEM_LOGGER_MODE.
//
// Usage:
//     p01_kernel_smoke --duration 10 [--db kernel_smoke.db] [--keep-db]

#include <windows.h>

#include <sqlite3.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <thread>
#include <nlohmann/json.hpp>

#include "collector/EventRecord.h"
#include "collector/KrabsConsumer.h"
#include "collector/SqliteWriter.h"
#include "common/Logging.h"

using namespace angelia;

namespace {

bool is_elevated() {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return false;
    TOKEN_ELEVATION elev{};
    DWORD sz = 0;
    const bool ok = GetTokenInformation(tok, TokenElevation, &elev, sizeof(elev), &sz);
    CloseHandle(tok);
    return ok && elev.TokenIsElevated;
}

struct Args {
    std::chrono::seconds       duration{10};
    std::filesystem::path      db{"kernel_smoke.db"};
    bool                       keep_db = true;
    std::filesystem::path      stats_json;
    collector::KrabsConsumer::Providers providers;   // all-on default
};

Args parse(int argc, char** argv) {
    Args a;
    bool explicit_providers = false;
    for (int i = 1; i < argc; ++i) {
        std::string_view k = argv[i];
        if      (k == "--duration" && i + 1 < argc) a.duration = std::chrono::seconds{std::atoi(argv[++i])};
        else if (k == "--db"       && i + 1 < argc) a.db       = argv[++i];
        else if (k == "--keep-db")                  a.keep_db  = true;
        else if (k == "--discard-db")               a.keep_db  = false;
        else if (k == "--stats-json" && i + 1 < argc) a.stats_json = argv[++i];
        else if (k == "--help" || k == "-h") {
            std::puts("usage: angelia collect [--duration SECONDS] [--db PATH] [--providers process,image,file,registry] [--stats-json PATH] [--discard-db]");
            std::exit(0);
        }
        else if (k == "--providers" && i + 1 < argc) {
            // Comma-separated subset from {process,image,file,registry}.
            explicit_providers = true;
            a.providers = {false, false, false, false};
            std::string_view csv = argv[++i];
            std::size_t start = 0;
            while (start <= csv.size()) {
                auto end = csv.find(',', start);
                if (end == std::string_view::npos) end = csv.size();
                auto tok = csv.substr(start, end - start);
                if      (tok == "process")  a.providers.process    = true;
                else if (tok == "image")    a.providers.image_load = true;
                else if (tok == "file")     a.providers.file_io    = true;
                else if (tok == "registry") a.providers.registry   = true;
                else if (!tok.empty()) {
                    std::fprintf(stderr, "unknown provider: %.*s\n",
                                 (int)tok.size(), tok.data());
                    std::exit(2);
                }
                start = end + 1;
            }
        }
        else { std::fprintf(stderr, "unknown arg: %.*s\n", (int)k.size(), k.data()); std::exit(2); }
    }
    (void)explicit_providers;
    if (a.duration.count()<1 || a.duration.count()>86400) {
        std::fprintf(stderr,"duration must be 1..86400 seconds\n");
        std::exit(2);
    }
    return a;
}

void report_from_db(const std::filesystem::path& db) {
    sqlite3* raw = nullptr;
    const auto s = db.u8string();
    if (sqlite3_open(reinterpret_cast<const char*>(s.c_str()), &raw) != SQLITE_OK) {
        std::printf("  (cannot open %s: %s)\n", db.string().c_str(),
                    raw ? sqlite3_errmsg(raw) : "?");
        if (raw) sqlite3_close_v2(raw);
        return;
    }

    // Per-kind breakdown.
    std::printf("\nper-kind breakdown:\n");
    const char* qk = "SELECT kind, COUNT(*) FROM events GROUP BY kind ORDER BY 2 DESC;";
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(raw, qk, -1, &st, nullptr) == SQLITE_OK) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            int kind = sqlite3_column_int(st, 0);
            int64_t c = sqlite3_column_int64(st, 1);
            std::printf("  %-18s : %lld\n",
                collector::to_string(static_cast<collector::EventKind>(kind)),
                (long long)c);
        }
        sqlite3_finalize(st);
    }

    std::printf("\nunknown events by provider and ID:\n");
    if (sqlite3_prepare_v2(raw,
            "SELECT provider,event_id,COUNT(*) FROM events WHERE kind=0 GROUP BY provider,event_id ORDER BY 3 DESC LIMIT 20",
            -1,&st,nullptr)==SQLITE_OK) {
        while (sqlite3_step(st)==SQLITE_ROW)
            std::printf("  provider=%d id=%d count=%lld\n",sqlite3_column_int(st,0),
                sqlite3_column_int(st,1),static_cast<long long>(sqlite3_column_int64(st,2)));
        sqlite3_finalize(st);
    }

    // Top processes by event count. Group by pid; look up the first name we
    // saw per pid (ProcessStart material) as a hint.
    std::printf("\ntop 10 pids by event count:\n");
    const char* qp = R"(
        SELECT pid, COUNT(*) AS n,
               (SELECT name FROM events e2
                 WHERE e2.pid = e1.pid AND e2.kind IN (2, 3)
                 ORDER BY e2.timestamp_100ns LIMIT 1) AS hint
        FROM events e1
        GROUP BY pid
        ORDER BY n DESC LIMIT 10;
    )";
    if (sqlite3_prepare_v2(raw, qp, -1, &st, nullptr) == SQLITE_OK) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            int pid   = sqlite3_column_int(st, 0);
            int64_t n = sqlite3_column_int64(st, 1);
            const unsigned char* hint = sqlite3_column_text(st, 2);
            std::printf("  pid=%-6d n=%-8lld %s\n",
                        pid, (long long)n, hint ? (const char*)hint : "");
        }
        sqlite3_finalize(st);
    }
    sqlite3_close_v2(raw);
}

}  // namespace

int angelia_cli_run_collect(int argc, char** argv) {
    common::init_logging();
    Args a = parse(argc, argv);
    if (!is_elevated()) {
        std::fprintf(stderr,
            "p01_kernel_smoke: not elevated. Kernel ETW sessions require "
            "Administrator. Re-run from an elevated PowerShell.\n");
        return 2;
    }

    std::error_code ec;
    if (std::filesystem::exists(a.db)) {
        std::fprintf(stderr,"collect: refusing to overwrite %s\n",a.db.string().c_str());
        return 2;
    }

    collector::WriterConfig cfg;
    cfg.batch_events   = 4096;
    cfg.queue_capacity = 1u << 17;
    collector::SqliteWriter writer(a.db, cfg);
    writer.start();

    collector::KrabsConsumer consumer(writer);
    try {
        consumer.start("angelia-p01", a.providers);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "kernel consumer failed to start: %s\n", e.what());
        return 1;
    }

    std::fprintf(stderr, "p01_kernel_smoke: collecting for %llds ...\n",
                 (long long)a.duration.count());
    const auto t0 = std::chrono::steady_clock::now();
    std::this_thread::sleep_for(a.duration);
    const auto etw = consumer.query_loss_stats();
    consumer.stop();
    std::this_thread::sleep_for(std::chrono::milliseconds{500});   // drain
    writer.stop();
    writer.finalise_latency_quantiles();
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0).count();

    const auto& m = writer.metrics();
    const auto committed   = m.events_committed.load();
    const auto pool_drops  = m.pool_drops.load();
    const auto queue_drops = m.queue_drops.load();
    std::printf("\n=== Stage 1 smoke ===\n");
    std::printf("duration              : %llds (%lld ms)\n",
                (long long)a.duration.count(), (long long)elapsed);
    std::printf("committed             : %llu\n", (unsigned long long)committed);
    std::printf("pool drops            : %llu\n", (unsigned long long)pool_drops);
    std::printf("queue drops           : %llu\n", (unsigned long long)queue_drops);
    if (etw.available)
        std::printf("ETW lost events/buffers: %u / %u (realtime %u)\n",
            etw.events_lost,etw.log_buffers_lost,etw.realtime_buffers_lost);
    else std::printf("ETW loss statistics   : unavailable\n");
    std::printf("throughput            : %.0f ev/s\n",
                elapsed > 0 ? double(committed) * 1000.0 / double(elapsed) : 0.0);
    std::printf("queue depth max       : %llu\n",
                (unsigned long long)m.queue_depth_max.load());
    std::printf("commit us p50/p99/max : %llu / %llu / %llu\n",
                (unsigned long long)m.commit_latency_p50_est_us.load(),
                (unsigned long long)m.commit_latency_p99_est_us.load(),
                (unsigned long long)m.commit_latency_max_us.load());

    report_from_db(a.db);

    if (!a.stats_json.empty()) {
        nlohmann::json stats={{"duration_seconds",a.duration.count()},
            {"events_committed",committed},{"pool_drops",pool_drops},
            {"queue_drops",queue_drops},{"etw_stats_available",etw.available}};
        if (etw.available) {
            stats["etw_events_lost"]=etw.events_lost;
            stats["etw_log_buffers_lost"]=etw.log_buffers_lost;
            stats["etw_realtime_buffers_lost"]=etw.realtime_buffers_lost;
        }
        std::ofstream out(a.stats_json);
        if (!out) { std::fprintf(stderr,"cannot write stats: %s\n",a.stats_json.string().c_str()); return 1; }
        out << stats.dump(2);
    }

    if (!a.keep_db) {
        std::filesystem::remove(a.db, ec);
        std::filesystem::remove(std::filesystem::path{a.db}.replace_extension(".db-wal"), ec);
        std::filesystem::remove(std::filesystem::path{a.db}.replace_extension(".db-shm"), ec);
    } else {
        std::printf("\nkept: %s\n", a.db.string().c_str());
    }
    return 0;
}
