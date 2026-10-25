// Stage 5 — per-incident integration report.
//
// Composes into a single self-contained HTML page:
//   * the static PE score for the target binary  (Component 3)
//   * the behavioural score for any PID we have timeline data for
//   * one card per crash artifact with the MSEC verdict + evidence
//   * a memory-forensics inventory summary if provided
//
// Cross-component plumbing (the "feeds into Component 3" wire): any
// crash artifact whose verdict.bucket ∈ {Exploitable,
// ProbablyExploitable} that targets the report's --binary adds a
// weighted 'confirmed-crash-<bucket>' feature to the static finding.
// The augmented score is what the report headlines.
//
//   incident_report --out report.html
//                   [--binary path\to\target.exe]
//                   [--triage crash1.json --triage crash2.json ...]
//                   [--timeline collector.db [--pid N]]
//                   [--inventory mem_inventory.json]
//                   [--title "Incident 2026-08-27"]

#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

#include <fmt/format.h>

#include "crashtriage/CrashArtifact.h"
#include "riskscore/BehavioralScorer.h"
#include "riskscore/StaticScorer.h"

namespace fs = std::filesystem;
using json  = nlohmann::json;
namespace ac = angelia::crashtriage;
namespace ar = angelia::riskscore;

namespace {

struct Args {
    fs::path out;
    fs::path binary;
    std::vector<fs::path> triage;
    fs::path timeline_db;
    std::optional<uint32_t> pid;
    fs::path inventory;
    std::string title;
};

[[noreturn]] void die(const std::string& msg) {
    std::fprintf(stderr, "incident_report: %s\n", msg.c_str());
    std::exit(2);
}

Args parse(int argc, char** argv) {
    Args a;
    for (int i = 1; i < argc; ++i) {
        std::string_view k = argv[i];
        auto need = [&]() -> std::string {
            if (i + 1 >= argc) die("missing value for " + std::string(k));
            return argv[++i];
        };
        if      (k == "--out")       a.out       = need();
        else if (k == "--binary")    a.binary    = need();
        else if (k == "--triage")    a.triage.emplace_back(need());
        else if (k == "--timeline")  a.timeline_db = need();
        else if (k == "--pid")       a.pid       = static_cast<uint32_t>(std::atoi(need().c_str()));
        else if (k == "--inventory") a.inventory = need();
        else if (k == "--title")     a.title     = need();
        else if (k == "-h" || k == "--help") {
            std::printf("usage: incident_report --out <path.html> "
                        "[--binary PATH] [--triage PATH ...] "
                        "[--timeline DB [--pid N]] [--inventory PATH] "
                        "[--title TITLE]\n");
            std::exit(0);
        }
        else die("unknown arg: " + std::string(k));
    }
    if (a.out.empty()) die("--out is required");
    if (a.title.empty()) {
        char buf[32];
        std::time_t now = std::time(nullptr);
        std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M UTC", std::gmtime(&now));
        a.title = std::string("Incident report — ") + buf;
    }
    return a;
}

std::string html_escape(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '&':  out += "&amp;";  break;
            case '<':  out += "&lt;";   break;
            case '>':  out += "&gt;";   break;
            case '"':  out += "&quot;"; break;
            case '\'': out += "&#39;";  break;
            default:   out.push_back(c);
        }
    }
    return out;
}

// Read+parse a crash artifact. Returns nullopt on failure (but prints
// diagnostic to stderr).
std::optional<ac::CrashArtifact> load_artifact(const fs::path& p) {
    std::ifstream f(p);
    if (!f) { std::fprintf(stderr, "cannot open %s\n", p.string().c_str()); return std::nullopt; }
    std::stringstream ss; ss << f.rdbuf();
    ac::CrashArtifact a;
    std::string err;
    if (!ac::from_json_str(ss.str(), a, err)) {
        std::fprintf(stderr, "%s: %s\n", p.string().c_str(), err.c_str()); return std::nullopt;
    }
    return a;
}

// If the artifact targets our --binary, translate its verdict into a
// static-scorer Feature. Skips artifacts with no verdict block, or with
// buckets that carry no signal.
std::optional<ar::Feature> triage_to_feature(
    const fs::path& binary,
    const ac::CrashArtifact& art)
{
    if (!art.verdict) return std::nullopt;
    // Path match is best-effort: crash artifacts may store a relative
    // path with forward or back slashes. Compare filenames only.
    if (!binary.empty() && !art.binary_path.empty()) {
        auto bin_name  = fs::path{binary}.filename().string();
        auto crash_bin = fs::path{art.binary_path}.filename().string();
        if (bin_name != crash_bin) return std::nullopt;
    }
    const auto b = art.verdict->bucket;
    double w = 0.0;
    switch (b) {
        case ac::MsecBucket::Exploitable:            w = 0.50; break;
        case ac::MsecBucket::ProbablyExploitable:    w = 0.30; break;
        case ac::MsecBucket::Unknown:                w = 0.05; break;
        case ac::MsecBucket::ProbablyNotExploitable: w = 0.0;  break;
        case ac::MsecBucket::NotExploitable:         w = 0.0;  break;
        default: return std::nullopt;
    }
    w *= std::clamp(art.verdict->confidence, 0.0, 1.0);
    if (w <= 0.0) return std::nullopt;

    ar::Feature f;
    f.name = std::string("confirmed-crash-") + ac::to_string(b);
    f.evidence = fmt::format(
        "P0.4/P0.5 pipeline observed a {} crash on {} (confidence {:.2f}); {}",
        ac::to_string(b),
        fs::path{art.binary_path}.filename().string(),
        art.verdict->confidence,
        art.verdict->rationale);
    f.weight = w;
    return f;
}

// Small helpers for HTML rendering.
const char* bucket_class(ac::MsecBucket b) {
    switch (b) {
        case ac::MsecBucket::Exploitable:            return "b-exp";
        case ac::MsecBucket::ProbablyExploitable:    return "b-pexp";
        case ac::MsecBucket::Unknown:                return "b-unk";
        case ac::MsecBucket::ProbablyNotExploitable: return "b-pnexp";
        case ac::MsecBucket::NotExploitable:         return "b-nexp";
        default:                                     return "b-unk";
    }
}

std::string render_static(const ar::StaticFinding& f) {
    std::ostringstream o;
    o << "<section class='card'><h2>Static risk score</h2>";
    if (!f.ok) {
        o << "<p class='err'>parse failed: " << html_escape(f.error) << "</p></section>";
        return o.str();
    }
    o << fmt::format("<p class='meta'>{}   image_base=<code>0x{:x}</code>  "
                     "entry=<code>0x{:x}</code>  imports={}</p>",
                     html_escape(f.path.string()), f.image_base, f.entry_point,
                     f.import_count);
    o << fmt::format("<p class='score'>score <span class='big'>{:.3f}</span> / 1.000</p>",
                     f.score);
    o << "<h3>Features</h3><table><thead><tr>"
         "<th>name</th><th>weight</th><th>evidence</th></tr></thead><tbody>";
    if (f.features.empty()) o << "<tr><td colspan='3' class='dim'>none matched</td></tr>";
    for (const auto& x : f.features)
        o << fmt::format("<tr><td><code>{}</code></td><td>{:.2f}</td><td>{}</td></tr>",
                         html_escape(x.name), x.weight, html_escape(x.evidence));
    o << "</tbody></table><h3>Sections</h3><table><thead><tr><th>name</th>"
         "<th>virt</th><th>raw</th><th>entropy</th><th>flags</th></tr></thead><tbody>";
    for (const auto& s : f.sections) {
        std::string flags;
        if (s.executable) flags.push_back('X'); else flags.push_back('-');
        if (s.writable)   flags.push_back('W'); else flags.push_back('-');
        if (s.exec_and_writable) flags += "  W^X!";
        std::string tint;
        if (s.entropy >= 7.5) tint = " class='hot'";
        else if (s.entropy >= 7.0) tint = " class='warm'";
        o << fmt::format(
            "<tr><td><code>{}</code></td><td>0x{:x}</td><td>0x{:x}</td>"
            "<td{}>H={:.2f}</td><td><code>{}</code></td></tr>",
            html_escape(s.name), s.virtual_size, s.raw_size, tint,
            s.entropy, flags);
    }
    o << "</tbody></table></section>";
    return o.str();
}

std::string render_triage(const ac::CrashArtifact& a) {
    std::ostringstream o;
    const std::string bucket = a.verdict ? ac::to_string(a.verdict->bucket) : "NotClassified";
    const char* cls          = a.verdict ? bucket_class(a.verdict->bucket) : "b-unk";
    const double conf        = a.verdict ? a.verdict->confidence : 0.0;

    o << fmt::format(
        "<section class='card'><h2>Crash triage: <span class='pill {}'>{}</span>"
        " <span class='dim'>conf {:.2f}</span></h2>",
        cls, html_escape(bucket), conf);

    o << fmt::format(
        "<p class='meta'><code>{}</code> &middot; input <code>{}</code> &middot; "
        "captured {}</p>",
        html_escape(a.binary_path), html_escape(a.input_path),
        html_escape(a.capture_iso8601_utc));

    o << fmt::format(
        "<p>exception <code>0x{:08x}</code>  fault <code>0x{:016x}</code>  "
        "RIP <code>0x{:016x}</code>  RSP <code>0x{:016x}</code></p>",
        a.exception_code, a.fault_address, a.registers.rip, a.registers.rsp);

    if (a.analysis) {
        o << fmt::format("<p>faulting insn: <code>{}</code></p>",
                         html_escape(a.analysis->zydis_disasm));
        o << "<h3>Evidence</h3><table><thead><tr><th>category</th><th>slug</th>"
             "<th>detail</th></tr></thead><tbody>";
        for (const auto& e : a.analysis->evidence)
            o << fmt::format(
                "<tr><td><code>{}</code></td><td><code>{}</code></td><td>{}</td></tr>",
                html_escape(e.category), html_escape(e.slug), html_escape(e.detail));
        o << "</tbody></table>";
    }
    if (a.verdict) {
        o << fmt::format("<h3>Verdict rationale</h3><p>{}</p>",
                         html_escape(a.verdict->rationale));
        if (!a.verdict->evidence_slugs.empty()) {
            o << "<p class='dim'>supporting slugs:</p><ul>";
            for (const auto& s : a.verdict->evidence_slugs)
                o << "<li><code>" << html_escape(s) << "</code></li>";
            o << "</ul>";
        }
    }
    // Mitigation flags — brief.
    o << "<h3>Mitigations at capture</h3><ul class='mitigation-list'>";
    auto mit = [&](const char* label, bool on) {
        o << fmt::format("<li class='{}'><code>{}</code>: {}</li>",
                         on ? "on" : "off", label, on ? "on" : "off");
    };
    mit("DEP",             a.mitigations.dep_enabled);
    mit("ASLR (bottom-up)",a.mitigations.aslr_bottom_up);
    mit("ASLR (high-ent)", a.mitigations.aslr_high_entropy);
    mit("CFG",             a.mitigations.cfg_enabled);
    mit("CET shadow stack",a.mitigations.cet_user_shadow_stack);
    mit("SEHOP",           a.mitigations.sehop_enabled);
    o << "</ul></section>";
    return o.str();
}

std::string render_behaviour(const ar::BehavioralReport& r,
                              std::optional<uint32_t> only_pid) {
    std::ostringstream o;
    o << "<section class='card'><h2>Behavioural activity</h2>";
    if (!r.ok) {
        o << "<p class='err'>" << html_escape(r.error) << "</p></section>";
        return o.str();
    }
    o << fmt::format("<p class='meta'>{} events across {} pids"
                     "{}</p>",
                     r.total_events, r.distinct_pids,
                     only_pid ? " (report shows " + std::to_string(*only_pid) + " only)" : "");
    if (r.pids.empty()) { o << "</section>"; return o.str(); }

    // If pid filter set, show only that; else top 10 by score.
    std::vector<ar::PidFeatures> show;
    if (only_pid) {
        for (const auto& p : r.pids) if (p.pid == *only_pid) show.push_back(p);
    } else {
        for (std::size_t i = 0; i < r.pids.size() && i < 10; ++i)
            if (r.pids[i].score > 0.0 || i < 3) show.push_back(r.pids[i]);
    }

    o << "<table><thead><tr><th>pid</th><th>image</th><th>score</th>"
         "<th>events</th><th>starts</th><th>loads</th><th>writes</th>"
         "<th>reg-sets</th><th>features</th></tr></thead><tbody>";
    for (const auto& p : show) {
        std::string feats;
        for (auto& x : p.features) {
            if (!feats.empty()) feats += ", ";
            feats += x.name;
        }
        o << fmt::format(
            "<tr><td>{}</td><td><code>{}</code></td>"
            "<td>{:.3f}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td>"
            "<td>{}</td></tr>",
            p.pid, html_escape(p.image_hint), p.score, p.event_count,
            p.process_starts, p.image_loads, p.file_writes, p.reg_sets,
            html_escape(feats));
    }
    o << "</tbody></table></section>";
    return o.str();
}

std::string render_inventory(const json& j) {
    std::ostringstream o;
    o << "<section class='card'><h2>Memory-forensics inventory</h2>";
    std::size_t raw_only = j.value("raw_only_count", std::size_t{0});
    auto entries = j.value("entries", json::array());
    o << fmt::format("<p class='meta'>{} entries &middot; <b>{}</b> present only in dump; investigate timing and source coverage</p>",
                     entries.size(), raw_only);
    o << "<table><thead><tr><th>pid</th><th>image (raw)</th><th>image (live)</th>"
         "<th>eprocess</th><th>comparison</th></tr></thead><tbody>";
    for (const auto& e : entries) {
        const bool h = e.value("raw_only", false);
        o << fmt::format(
            "<tr class='{}'><td>{}</td><td><code>{}</code></td>"
            "<td><code>{}</code></td><td><code>{}</code></td><td>{}</td></tr>",
            h ? "review" : "",
            e.value("pid", 0),
            html_escape(e.value("image_raw", "")),
            html_escape(e.value("image_live", "")),
            html_escape(e.value("eprocess_va", "")),
            h ? "dump only; review" : e.value("snapshot_only", false) ? "snapshot only; review" : "matched");
    }
    o << "</tbody></table></section>";
    return o.str();
}

constexpr const char* kCss = R"CSS(
  :root {
    --bg:#0f1216; --card:#171b21; --text:#e6e8eb; --dim:#9aa2ab;
    --border:#252b33; --accent:#8ab4ff;
    --exp:#ff6b6b; --pexp:#ffb84d; --unk:#9aa2ab; --pnexp:#8bd68f; --nexp:#5cd39a;
  }
  * { box-sizing:border-box; }
  body { font: 14px/1.5 -apple-system, "Segoe UI", Roboto, sans-serif;
         background:var(--bg); color:var(--text); margin:0; padding:32px;
         max-width:1200px; margin-inline:auto; }
  h1 { font-size:22px; margin:0 0 8px; }
  h2 { font-size:16px; margin:24px 0 12px; color:var(--accent); }
  h3 { font-size:13px; margin:16px 0 6px; color:var(--dim); text-transform:uppercase; letter-spacing:.05em; }
  .card { background:var(--card); border:1px solid var(--border);
          border-radius:8px; padding:20px 24px; margin:16px 0; }
  .meta { color:var(--dim); margin:2px 0 12px; font-size:12px; }
  .dim  { color:var(--dim); }
  .err  { color:var(--exp); }
  .score .big { font-size:22px; color:var(--accent); }
  code  { font: 12px/1.5 "SF Mono", Consolas, monospace; color:#c9d0d8; }
  table { border-collapse:collapse; width:100%; margin-top:6px; }
  th, td { text-align:left; padding:6px 10px; border-bottom:1px solid var(--border);
           vertical-align:top; font-size:12px; }
  th { color:var(--dim); font-weight:600; text-transform:uppercase; letter-spacing:.04em; }
  tr.review { background:rgba(255,194,107,0.10); }
  tr td.hot  { color:var(--exp); font-weight:600; }
  tr td.warm { color:var(--pexp); }
  .pill { display:inline-block; padding:2px 8px; border-radius:12px;
          font-size:12px; margin-left:6px; }
  .b-exp   { background:var(--exp);   color:#111; }
  .b-pexp  { background:var(--pexp);  color:#111; }
  .b-unk   { background:var(--unk);   color:#111; }
  .b-pnexp { background:var(--pnexp); color:#111; }
  .b-nexp  { background:var(--nexp);  color:#111; }
  .mitigation-list { list-style:none; padding:0; display:flex; flex-wrap:wrap; gap:8px; }
  .mitigation-list li { padding:2px 8px; border-radius:4px; background:#0e1116;
                        border:1px solid var(--border); font-size:12px; }
  .mitigation-list li.on { border-color:var(--nexp); color:#c9f0d8; }
  details { margin-top:12px; }
  summary { cursor:pointer; color:var(--dim); }
  pre { background:#0b0d10; padding:12px; overflow-x:auto; border-radius:6px;
        font-size:11px; }
)CSS";

}  // namespace

int angelia_cli_run_report(int argc, char** argv) {
    Args a = parse(argc, argv);

    // Load triage artifacts first so we can augment the static score.
    std::vector<ac::CrashArtifact> arts;
    for (const auto& p : a.triage) {
        if (auto art = load_artifact(p)) arts.push_back(std::move(*art));
    }

    // Score the target binary if given, then augment with any matching
    // crash-triage findings.
    std::optional<ar::StaticFinding> stat;
    if (!a.binary.empty()) {
        auto sf = ar::score_pe(a.binary);
        for (const auto& art : arts) {
            if (auto feat = triage_to_feature(a.binary, art)) {
                sf.features.push_back(*feat);
                sf.score = std::min(1.0, sf.score + feat->weight);
            }
        }
        stat = std::move(sf);
    }

    // Behavioural, if requested.
    std::optional<ar::BehavioralReport> beh;
    if (!a.timeline_db.empty()) {
        beh = ar::score_timeline(a.timeline_db, a.pid);
    }

    // Memory inventory, if provided (raw JSON — we only display).
    std::optional<json> inv;
    if (!a.inventory.empty()) {
        std::ifstream f(a.inventory);
        if (!f) std::fprintf(stderr, "cannot open %s\n", a.inventory.string().c_str());
        else {
            try { json j; f >> j; inv = std::move(j); }
            catch (const std::exception& e) {
                std::fprintf(stderr, "inventory parse: %s\n", e.what());
            }
        }
    }

    // Build HTML.
    std::ostringstream o;
    o << "<!doctype html><html><head><meta charset='utf-8'>"
         "<meta name='viewport' content='width=device-width,initial-scale=1'>"
         "<title>" << html_escape(a.title) << "</title>"
         "<style>" << kCss << "</style></head><body>";
    o << "<h1>" << html_escape(a.title) << "</h1>";
    o << fmt::format("<p class='meta'>{} artifacts &middot; "
                     "binary: {} &middot; timeline: {} &middot; "
                     "inventory: {}</p>",
                     arts.size(),
                     a.binary.empty()      ? "(none)" : html_escape(a.binary.string()),
                     a.timeline_db.empty() ? "(none)" : html_escape(a.timeline_db.string()),
                     a.inventory.empty()   ? "(none)" : html_escape(a.inventory.string()));

    if (stat) o << render_static(*stat);
    for (const auto& art : arts) o << render_triage(art);
    if (beh)  o << render_behaviour(*beh, a.pid);
    if (inv)  o << render_inventory(*inv);

    // Raw source at bottom for pipeline reconstruction and review.
    o << "<details><summary>Raw sources (JSON)</summary><pre>";
    if (stat) {
        o << html_escape("== static ==\n") << html_escape(ar::to_json(*stat)) << "\n";
    }
    for (const auto& art : arts) {
        o << html_escape("== triage: " + art.binary_path + " ==\n")
          << html_escape(ac::to_json(art)) << "\n";
    }
    if (inv) o << html_escape("== inventory ==\n") << html_escape(inv->dump(2)) << "\n";
    o << "</pre></details></body></html>\n";

    std::ofstream f(a.out, std::ios::binary | std::ios::trunc);
    if (!f) die("cannot write " + a.out.string());
    const auto s = o.str();
    f.write(s.data(), static_cast<std::streamsize>(s.size()));
    std::printf("wrote %s (%zu bytes)\n", a.out.string().c_str(), s.size());
    return 0;
}
