#include "riskscore/BehavioralScorer.h"

#include "collector/EventRecord.h"   // EventKind

#include <sqlite3.h>

#include <fmt/format.h>

#include <algorithm>
#include <sstream>
#include <string>
#include <unordered_map>

namespace angelia::riskscore {

namespace {

// Small deterministic-lifetime sqlite helper. Reused only from this
// module — the collector uses common::Sqlite for writes.
struct Db {
    sqlite3* h = nullptr;
    ~Db() { if (h) sqlite3_close_v2(h); }
    bool open(const std::filesystem::path& p, std::string& err) {
        const auto s = p.u8string();
        if (sqlite3_open_v2(reinterpret_cast<const char*>(s.c_str()),
                            &h, SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) {
            err = fmt::format("sqlite open({}): {}", p.string(), h ? sqlite3_errmsg(h) : "?");
            return false;
        }
        return true;
    }
};

struct Stmt {
    sqlite3_stmt* s = nullptr;
    ~Stmt() { if (s) sqlite3_finalize(s); }
    bool prepare(sqlite3* h, const char* sql, std::string& err) {
        if (sqlite3_prepare_v2(h, sql, -1, &s, nullptr) != SQLITE_OK) {
            err = fmt::format("prepare({}): {}", sql, sqlite3_errmsg(h));
            return false;
        }
        return true;
    }
};

// A tiny set of Run-key path fragments — case-insensitive substring
// match. Real threat hunts widen this; the point here is to prove signal
// separation, not to build a full detection surface.
bool is_run_key_path(std::string_view name) {
    static const char* frags[] = {
        "\\microsoft\\windows\\currentversion\\run",
        "\\microsoft\\windows\\currentversion\\runonce",
        "\\services\\",
        "\\image file execution options\\",
    };
    std::string lc; lc.reserve(name.size());
    for (char c : name) lc.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    for (const char* f : frags) {
        if (lc.find(f) != std::string::npos) return true;
    }
    return false;
}

bool is_user_writable_dll_path(std::string_view name) {
    static const char* frags[] = {
        "\\appdata\\",
        "\\temp\\",
        "\\downloads\\",
        "\\users\\public\\",
        "\\programdata\\",   // less-privileged, world-writable subset
    };
    std::string lc; lc.reserve(name.size());
    for (char c : name) lc.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    for (const char* f : frags) {
        if (lc.find(f) != std::string::npos) return true;
    }
    return false;
}

double clamp01(double v) { return v < 0.0 ? 0.0 : (v > 1.0 ? 1.0 : v); }

}  // namespace

BehavioralReport score_timeline(const std::filesystem::path& db_path,
                                std::optional<uint32_t> only_pid) {
    BehavioralReport out;

    Db db;
    if (!db.open(db_path, out.error)) return out;

    // Sanity: is this actually a collector DB?
    sqlite3_stmt* check = nullptr;
    if (sqlite3_prepare_v2(db.h,
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='events'",
            -1, &check, nullptr) != SQLITE_OK ||
        sqlite3_step(check) != SQLITE_ROW ||
        sqlite3_column_int(check, 0) == 0) {
        if (check) sqlite3_finalize(check);
        out.error = "no 'events' table found in DB";
        return out;
    }
    sqlite3_finalize(check);

    // Aggregates. One pass over events for the per-kind counts;
    // subsequent passes for distinct counts and pattern flags.
    std::unordered_map<uint32_t, PidFeatures> map;

    // Pass 1: per-pid per-kind counts + first/last seen + image hint.
    const char* q1_all =
        "SELECT pid, kind, COUNT(*), MIN(timestamp_100ns), MAX(timestamp_100ns) "
        "FROM events GROUP BY pid, kind";
    const char* q1_one =
        "SELECT pid, kind, COUNT(*), MIN(timestamp_100ns), MAX(timestamp_100ns) "
        "FROM events WHERE pid = ? GROUP BY pid, kind";
    Stmt s1;
    if (!s1.prepare(db.h, only_pid ? q1_one : q1_all, out.error)) return out;
    if (only_pid) sqlite3_bind_int64(s1.s, 1, *only_pid);
    while (sqlite3_step(s1.s) == SQLITE_ROW) {
        const auto pid    = static_cast<uint32_t>(sqlite3_column_int64(s1.s, 0));
        const auto kind   = sqlite3_column_int(s1.s, 1);
        const auto cnt    = static_cast<uint64_t>(sqlite3_column_int64(s1.s, 2));
        const auto tmin   = static_cast<uint64_t>(sqlite3_column_int64(s1.s, 3));
        const auto tmax   = static_cast<uint64_t>(sqlite3_column_int64(s1.s, 4));
        auto& f = map[pid];
        f.pid = pid;
        f.event_count += cnt;
        f.first_seen_100ns = f.first_seen_100ns
            ? std::min(f.first_seen_100ns, tmin) : tmin;
        f.last_seen_100ns  = std::max(f.last_seen_100ns, tmax);
        switch (static_cast<collector::EventKind>(kind)) {
            case collector::EventKind::ProcessStart:      f.process_starts += cnt; break;
            case collector::EventKind::ImageLoad:         f.image_loads    += cnt; break;
            case collector::EventKind::FileCreate:        f.file_creates   += cnt; break;
            case collector::EventKind::FileWrite:         f.file_writes    += cnt; break;
            case collector::EventKind::FileRead:          f.file_reads     += cnt; break;
            case collector::EventKind::FileDelete:        f.file_deletes   += cnt; break;
            case collector::EventKind::RegistrySetValue:  f.reg_sets       += cnt; break;
            case collector::EventKind::RegistryDeleteValue:
            case collector::EventKind::RegistryDeleteKey: f.reg_deletes    += cnt; break;
            default: break;
        }
    }

    // Pass 2: image hint (name of first ProcessStart / ImageLoad).
    Stmt s2;
    if (!s2.prepare(db.h,
        "SELECT pid, name FROM events "
        " WHERE kind IN (2, 4) AND name IS NOT NULL "
        " GROUP BY pid HAVING MIN(timestamp_100ns)", out.error)) return out;
    while (sqlite3_step(s2.s) == SQLITE_ROW) {
        const auto pid = static_cast<uint32_t>(sqlite3_column_int64(s2.s, 0));
        auto it = map.find(pid);
        if (it == map.end()) continue;
        const auto* n = sqlite3_column_text(s2.s, 1);
        if (n) it->second.image_hint = reinterpret_cast<const char*>(n);
    }

    // Pass 3: distinct file writes + distinct reg-keys touched.
    Stmt s3a, s3b;
    if (!s3a.prepare(db.h,
        "SELECT pid, COUNT(DISTINCT name) FROM events "
        "WHERE kind IN (6, 7) AND name IS NOT NULL GROUP BY pid", out.error)) return out;
    while (sqlite3_step(s3a.s) == SQLITE_ROW) {
        const auto pid = static_cast<uint32_t>(sqlite3_column_int64(s3a.s, 0));
        auto it = map.find(pid);
        if (it != map.end())
            it->second.distinct_files_written =
                static_cast<uint64_t>(sqlite3_column_int64(s3a.s, 1));
    }
    if (!s3b.prepare(db.h,
        "SELECT pid, COUNT(DISTINCT name) FROM events "
        "WHERE kind IN (11, 12, 13, 14) AND name IS NOT NULL GROUP BY pid",
        out.error)) return out;   // RegistryCreateKey..DeleteValue
    while (sqlite3_step(s3b.s) == SQLITE_ROW) {
        const auto pid = static_cast<uint32_t>(sqlite3_column_int64(s3b.s, 0));
        auto it = map.find(pid);
        if (it != map.end())
            it->second.distinct_regkeys_touched =
                static_cast<uint64_t>(sqlite3_column_int64(s3b.s, 1));
    }

    // Pass 4: per-row scan for run-key writes + user-writable DLL loads.
    // These need string inspection SQL-side is possible but keeping it
    // C++-side keeps the rule set live-editable without touching schema.
    Stmt s4;
    if (!s4.prepare(db.h,
        "SELECT pid, kind, name FROM events WHERE name IS NOT NULL "
        "AND kind IN (4, 13)", out.error)) return out;   // ImageLoad, RegistrySetValue
    while (sqlite3_step(s4.s) == SQLITE_ROW) {
        const auto pid  = static_cast<uint32_t>(sqlite3_column_int64(s4.s, 0));
        const auto kind = sqlite3_column_int(s4.s, 1);
        const auto* n_c = sqlite3_column_text(s4.s, 2);
        if (!n_c) continue;
        std::string_view n(reinterpret_cast<const char*>(n_c));
        auto it = map.find(pid);
        if (it == map.end()) continue;
        if (kind == static_cast<int>(collector::EventKind::ImageLoad) &&
            is_user_writable_dll_path(n)) it->second.dlls_from_user_writable++;
        else if (kind == static_cast<int>(collector::EventKind::RegistrySetValue) &&
                 is_run_key_path(n)) it->second.reg_run_persistence_hits++;
    }

    // Pass 5: kind bigrams per-PID. Ordered by timestamp within PID.
    // Small enough for our timelines; a real production path would
    // materialise this as a view.
    Stmt s5;
    if (!s5.prepare(db.h,
        "SELECT pid, kind FROM events ORDER BY pid, timestamp_100ns", out.error)) return out;
    uint32_t last_pid = 0; int32_t last_kind = -1;
    std::unordered_map<uint32_t,
        std::unordered_map<uint64_t, uint64_t>> bigrams;   // per-pid → (from<<8|to) → count
    while (sqlite3_step(s5.s) == SQLITE_ROW) {
        const auto pid  = static_cast<uint32_t>(sqlite3_column_int64(s5.s, 0));
        const auto kind = sqlite3_column_int(s5.s, 1);
        if (pid == last_pid && last_kind >= 0) {
            const uint64_t key = (static_cast<uint64_t>(last_kind) << 8) |
                                  static_cast<uint64_t>(kind);
            bigrams[pid][key]++;
        }
        last_pid  = pid;
        last_kind = kind;
    }
    for (auto& [pid, m] : bigrams) {
        auto it = map.find(pid);
        if (it == map.end()) continue;
        for (const auto& [k, v] : m) {
            BigramCount bc;
            bc.from_kind = static_cast<int32_t>((k >> 8) & 0xFF);
            bc.to_kind   = static_cast<int32_t>(k & 0xFF);
            bc.count     = v;
            it->second.transitions.push_back(bc);
        }
    }

    // Rules → features → score.
    for (auto& [pid, f] : map) {
        if (f.reg_run_persistence_hits > 0) {
            f.features.push_back({
                "reg-run-persistence",
                fmt::format("wrote to {} Run/RunOnce-adjacent key(s)",
                            f.reg_run_persistence_hits),
                0.40});
        }
        if (f.dlls_from_user_writable > 0) {
            f.features.push_back({
                "dll-from-user-writable",
                fmt::format("loaded {} image(s) from AppData/Temp/Downloads/ProgramData",
                            f.dlls_from_user_writable),
                0.30});
        }
        // Ransomware fanout: many distinct files written in the window.
        if (f.distinct_files_written >= 50) {
            f.features.push_back({
                "high-fanout-file-write",
                fmt::format("{} distinct files written", f.distinct_files_written),
                0.40});
        }
        // Canonical installer sequence: process started + loaded images +
        // wrote at least one file + wrote at least one registry value.
        if (f.process_starts > 0 && f.image_loads > 0 &&
            f.file_writes > 0 && f.reg_sets > 0) {
            f.features.push_back({
                "installation-flow",
                "PID exhibits ProcessStart + ImageLoad + FileWrite + RegSetValue",
                0.20});
        }
        double s = 0.0;
        for (auto& x : f.features) s += x.weight;
        f.score = clamp01(s);
    }

    out.ok = true;
    out.total_events = 0;
    for (const auto& [_, f] : map) out.total_events += f.event_count;
    out.distinct_pids = map.size();
    out.pids.reserve(map.size());
    for (auto& kv : map) out.pids.push_back(std::move(kv.second));
    std::sort(out.pids.begin(), out.pids.end(),
              [](const PidFeatures& a, const PidFeatures& b) { return a.score > b.score; });
    return out;
}

namespace {
std::string q(std::string_view v) {
    std::string s; s.reserve(v.size() + 2); s.push_back('"');
    for (char c : v) {
        switch (c) {
            case '"':  s += "\\\""; break;
            case '\\': s += "\\\\"; break;
            case '\n': s += "\\n";  break;
            case '\r': s += "\\r";  break;
            case '\t': s += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20)
                    s += fmt::format("\\u{:04x}", (unsigned)c);
                else s.push_back(c);
        }
    }
    s.push_back('"');
    return s;
}
}

std::string to_json(const BehavioralReport& r) {
    std::ostringstream os;
    os << "{\n  \"ok\": " << (r.ok ? "true" : "false") << ",\n";
    if (!r.ok) { os << "  \"error\": " << q(r.error) << "\n}\n"; return os.str(); }
    os << "  \"total_events\": " << r.total_events << ",\n";
    os << "  \"distinct_pids\": " << r.distinct_pids << ",\n";
    os << "  \"pids\": [";
    for (std::size_t i = 0; i < r.pids.size(); ++i) {
        const auto& p = r.pids[i];
        os << (i ? "," : "") << "\n    {"
           << "\"pid\":" << p.pid
           << ",\"image\":" << q(p.image_hint)
           << ",\"score\":" << fmt::format("{:.3f}", p.score)
           << ",\"events\":" << p.event_count
           << ",\"process_starts\":" << p.process_starts
           << ",\"image_loads\":" << p.image_loads
           << ",\"file_writes\":" << p.file_writes
           << ",\"file_creates\":" << p.file_creates
           << ",\"reg_sets\":" << p.reg_sets
           << ",\"distinct_files_written\":" << p.distinct_files_written
           << ",\"distinct_regkeys_touched\":" << p.distinct_regkeys_touched
           << ",\"dlls_from_user_writable\":" << p.dlls_from_user_writable
           << ",\"reg_run_persistence_hits\":" << p.reg_run_persistence_hits
           << ",\"features\":[";
        for (std::size_t k = 0; k < p.features.size(); ++k) {
            const auto& x = p.features[k];
            os << (k ? "," : "") << "{"
               << "\"name\":" << q(x.name)
               << ",\"weight\":" << fmt::format("{:.3f}", x.weight)
               << ",\"evidence\":" << q(x.evidence) << "}";
        }
        os << "]}";
    }
    os << "\n  ]\n}\n";
    return os.str();
}

}  // namespace angelia::riskscore
