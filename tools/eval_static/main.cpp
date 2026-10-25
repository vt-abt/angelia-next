// Stage 6 — precision/recall harness over the labeled corpus.
//
// Reads a JSON corpus of {path, label, family, mitigation} entries,
// runs the Stage 3 static scorer on each, optionally augments the
// score with any matching crash-triage artifact in --triage-dir
// (matching by binary basename), and sweeps a threshold to compute
// TP / FP / TN / FN + precision + recall + F1 per threshold.
//
// Emits three artifacts:
//   * per-binary CSV       (one row per binary with both scores)
//   * per-threshold CSV    (P/R/F1 across a threshold sweep)
//   * a compact summary JSON for the writeup pipeline
//
//   eval_static --corpus configs/eval_corpus.json
//               [--triage-dir case_study/triage/]
//               [--out-dir eval_out/]

#include <cstdio>
#include <cstdlib>
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
#include "riskscore/StaticScorer.h"

namespace fs = std::filesystem;
using json  = nlohmann::json;
namespace ac = angelia::crashtriage;
namespace ar = angelia::riskscore;

namespace {

struct CorpusEntry {
    fs::path    path;
    std::string label;        // "positive" or "negative"
    std::string family;
    std::string mitigation;
};

struct Row {
    CorpusEntry entry;
    ar::StaticFinding finding;   // baseline
    double      score_static    = 0.0;   // ==finding.score
    double      score_augmented = 0.0;   // finding.score + any triage augment
    std::string augment_hits;            // human-readable which artifact(s) fed the augment
};

struct MetricPoint {
    double  threshold;
    int     tp = 0, fp = 0, tn = 0, fn = 0;
    double  precision = 0.0, recall = 0.0, f1 = 0.0;
};

struct Args {
    fs::path corpus = "configs/eval_corpus.json";
    fs::path triage_dir;
    fs::path out_dir = "eval_out";
};

[[noreturn]] void die(const std::string& m) {
    std::fprintf(stderr, "eval_static: %s\n", m.c_str()); std::exit(2);
}

Args parse(int argc, char** argv) {
    Args a;
    for (int i = 1; i < argc; ++i) {
        std::string_view k = argv[i];
        auto need = [&]() -> std::string {
            if (i + 1 >= argc) die("missing value for " + std::string(k));
            return argv[++i];
        };
        if      (k == "--corpus")     a.corpus     = need();
        else if (k == "--triage-dir") a.triage_dir = need();
        else if (k == "--out-dir")    a.out_dir    = need();
        else if (k == "-h" || k == "--help") {
            std::printf("usage: eval_static [--corpus PATH] [--triage-dir PATH] [--out-dir PATH]\n");
            std::exit(0);
        }
        else die("unknown arg: " + std::string(k));
    }
    return a;
}

std::vector<CorpusEntry> load_corpus(const fs::path& p) {
    std::ifstream f(p);
    if (!f) die("cannot open corpus " + p.string());
    json j; f >> j;
    std::vector<CorpusEntry> out;
    for (const auto& e : j.at("binaries")) {
        CorpusEntry c;
        c.path       = e.at("path").get<std::string>();
        c.label      = e.at("label").get<std::string>();
        c.family     = e.value("family", "");
        c.mitigation = e.value("mitigation", "");
        out.push_back(std::move(c));
    }
    return out;
}

// Load all *.json in triage_dir as CrashArtifacts. Returns whatever
// parses cleanly — silently skips malformed / non-artifact files.
std::vector<ac::CrashArtifact> load_triage(const fs::path& dir) {
    std::vector<ac::CrashArtifact> out;
    if (dir.empty()) return out;
    if (!fs::exists(dir)) return out;
    for (const auto& de : fs::recursive_directory_iterator(dir)) {
        if (!de.is_regular_file()) continue;
        if (de.path().extension() != ".json") continue;
        std::ifstream f(de.path());
        if (!f) continue;
        std::stringstream ss; ss << f.rdbuf();
        ac::CrashArtifact a; std::string err;
        if (!ac::from_json_str(ss.str(), a, err)) continue;
        if (!a.verdict) continue;
        out.push_back(std::move(a));
    }
    return out;
}

// Same augmentation policy the incident_report uses; kept in sync with it.
double triage_augment_weight(ac::MsecBucket b, double confidence) {
    double base = 0.0;
    switch (b) {
        case ac::MsecBucket::Exploitable:            base = 0.50; break;
        case ac::MsecBucket::ProbablyExploitable:    base = 0.30; break;
        case ac::MsecBucket::Unknown:                base = 0.05; break;
        default: return 0.0;
    }
    if (confidence < 0.0) confidence = 0.0;
    if (confidence > 1.0) confidence = 1.0;
    return base * confidence;
}

double clamp01(double v) { return v < 0.0 ? 0.0 : (v > 1.0 ? 1.0 : v); }

MetricPoint metrics_at(const std::vector<Row>& rows, double t, bool augmented) {
    MetricPoint m; m.threshold = t;
    for (const auto& r : rows) {
        const double s = augmented ? r.score_augmented : r.score_static;
        const bool   flagged = s >= t;
        const bool   positive = (r.entry.label == "positive");
        if      ( positive &&  flagged) ++m.tp;
        else if (!positive &&  flagged) ++m.fp;
        else if (!positive && !flagged) ++m.tn;
        else                            ++m.fn;
    }
    m.precision = (m.tp + m.fp) > 0 ? double(m.tp) / (m.tp + m.fp) : 0.0;
    m.recall    = (m.tp + m.fn) > 0 ? double(m.tp) / (m.tp + m.fn) : 0.0;
    m.f1        = (m.precision + m.recall) > 0
                    ? 2 * m.precision * m.recall / (m.precision + m.recall) : 0.0;
    return m;
}

}  // namespace

int angelia_cli_run_eval(int argc, char** argv) {
    Args a = parse(argc, argv);
    auto corpus = load_corpus(a.corpus);
    if (corpus.empty()) die("corpus contains no binaries");
    auto triage = load_triage(a.triage_dir);
    std::fprintf(stderr, "corpus=%zu binaries; triage=%zu artifacts loaded\n",
                 corpus.size(), triage.size());

    std::vector<Row> rows;
    rows.reserve(corpus.size());

    for (const auto& c : corpus) {
        if (c.label != "positive" && c.label != "negative")
            die("invalid label for " + c.path.string() + ": " + c.label);
        Row r; r.entry = c;
        r.finding = ar::score_pe(c.path);
        if (!r.finding.ok)
            die("cannot score " + c.path.string() + ": " + r.finding.error);
        r.score_static    = r.finding.score;
        r.score_augmented = r.score_static;

        // Augment from triage artifacts whose binary_path filename matches
        // this corpus entry's filename.
        const auto want = c.path.filename().string();
        for (const auto& art : triage) {
            if (!art.verdict) continue;
            if (fs::path{art.binary_path}.filename().string() != want) continue;
            const double w = triage_augment_weight(art.verdict->bucket,
                                                    art.verdict->confidence);
            if (w <= 0.0) continue;
            r.score_augmented = clamp01(r.score_augmented + w);
            if (!r.augment_hits.empty()) r.augment_hits += "; ";
            r.augment_hits += fmt::format("{}(confidence={:.2f}, weight={:.2f})",
                                          ac::to_string(art.verdict->bucket),
                                          art.verdict->confidence, w);
        }
        rows.push_back(std::move(r));
    }

    std::error_code ec;
    fs::create_directories(a.out_dir, ec);
    if (ec) die("cannot create output directory " + a.out_dir.string() + ": " + ec.message());

    // --- Write per-binary CSV ------------------------------------------
    {
        std::ofstream f(a.out_dir / "per_binary.csv", std::ios::binary | std::ios::trunc);
        f << "path,label,family,mitigation,score_static,score_augmented,augment_hits,static_features\n";
        for (const auto& r : rows) {
            std::string feats;
            for (const auto& x : r.finding.features) {
                if (!feats.empty()) feats += "|";
                feats += x.name;
            }
            f << fmt::format("\"{}\",{},{},{},{:.3f},{:.3f},\"{}\",\"{}\"\n",
                             r.entry.path.string(), r.entry.label,
                             r.entry.family, r.entry.mitigation,
                             r.score_static, r.score_augmented,
                             r.augment_hits, feats);
        }
    }

    // --- Threshold sweep -----------------------------------------------
    std::vector<double> thresholds;
    for (double t = 0.05; t <= 0.75 + 1e-9; t += 0.05) thresholds.push_back(t);
    std::vector<MetricPoint> mstatic, maugmented;
    for (double t : thresholds) {
        mstatic.push_back(metrics_at(rows, t, /*augmented=*/false));
        maugmented.push_back(metrics_at(rows, t, /*augmented=*/true));
    }
    {
        std::ofstream f(a.out_dir / "sweep.csv", std::ios::binary | std::ios::trunc);
        f << "threshold,scorer,tp,fp,tn,fn,precision,recall,f1\n";
        for (const auto& m : mstatic)
            f << fmt::format("{:.2f},static,{},{},{},{},{:.3f},{:.3f},{:.3f}\n",
                             m.threshold, m.tp, m.fp, m.tn, m.fn,
                             m.precision, m.recall, m.f1);
        for (const auto& m : maugmented)
            f << fmt::format("{:.2f},augmented,{},{},{},{},{:.3f},{:.3f},{:.3f}\n",
                             m.threshold, m.tp, m.fp, m.tn, m.fn,
                             m.precision, m.recall, m.f1);
    }

    // --- Summary JSON --------------------------------------------------
    auto best_by_f1 = [](const std::vector<MetricPoint>& v) {
        MetricPoint best = v.front();
        for (const auto& m : v) if (m.f1 > best.f1) best = m;
        return best;
    };
    MetricPoint best_s = best_by_f1(mstatic);
    MetricPoint best_a = best_by_f1(maugmented);
    {
        json j;
        j["corpus_size"] = rows.size();
        j["positives"] = std::count_if(rows.begin(), rows.end(),
            [](const Row& r) { return r.entry.label == "positive"; });
        j["negatives"] = std::count_if(rows.begin(), rows.end(),
            [](const Row& r) { return r.entry.label == "negative"; });
        j["triage_artifacts_loaded"] = triage.size();

        auto pack = [](const MetricPoint& m) {
            return json{{"threshold", m.threshold}, {"tp", m.tp}, {"fp", m.fp},
                        {"tn", m.tn}, {"fn", m.fn},
                        {"precision", m.precision}, {"recall", m.recall}, {"f1", m.f1}};
        };
        j["best_static"]    = pack(best_s);
        j["best_augmented"] = pack(best_a);
        j["per_binary"]     = json::array();
        for (const auto& r : rows) {
            j["per_binary"].push_back({
                {"path",            r.entry.path.string()},
                {"label",           r.entry.label},
                {"family",          r.entry.family},
                {"mitigation",      r.entry.mitigation},
                {"score_static",    r.score_static},
                {"score_augmented", r.score_augmented},
                {"augment_hits",    r.augment_hits},
            });
        }
        std::ofstream f(a.out_dir / "summary.json", std::ios::binary | std::ios::trunc);
        f << j.dump(2);
    }

    // --- Console readout -----------------------------------------------
    std::printf("\n=== per-binary scores ===\n");
    std::printf("%-40s  %-9s  %-14s  %-6s  %-7s  %-7s\n",
                "path", "label", "family", "mitig", "static", "aug");
    for (const auto& r : rows) {
        std::printf("%-40s  %-9s  %-14s  %-6s  %-7.3f  %-7.3f%s\n",
                    r.entry.path.filename().string().c_str(),
                    r.entry.label.c_str(), r.entry.family.c_str(),
                    r.entry.mitigation.c_str(),
                    r.score_static, r.score_augmented,
                    r.augment_hits.empty() ? "" : "  <<");
    }

    std::printf("\n=== threshold sweep (static-only) ===\n");
    std::printf("%-6s  %-3s  %-3s  %-3s  %-3s  %-8s  %-8s  %-8s\n",
                "thr", "TP", "FP", "TN", "FN", "prec", "recall", "F1");
    for (const auto& m : mstatic)
        std::printf("%-6.2f  %-3d  %-3d  %-3d  %-3d  %-8.3f  %-8.3f  %-8.3f\n",
                    m.threshold, m.tp, m.fp, m.tn, m.fn,
                    m.precision, m.recall, m.f1);

    std::printf("\n=== threshold sweep (static + triage-augmented) ===\n");
    std::printf("%-6s  %-3s  %-3s  %-3s  %-3s  %-8s  %-8s  %-8s\n",
                "thr", "TP", "FP", "TN", "FN", "prec", "recall", "F1");
    for (const auto& m : maugmented)
        std::printf("%-6.2f  %-3d  %-3d  %-3d  %-3d  %-8.3f  %-8.3f  %-8.3f\n",
                    m.threshold, m.tp, m.fp, m.tn, m.fn,
                    m.precision, m.recall, m.f1);

    std::printf("\nBest F1 (static):    %.3f @ threshold=%.2f  P=%.3f R=%.3f\n",
                best_s.f1, best_s.threshold, best_s.precision, best_s.recall);
    std::printf("Best F1 (augmented): %.3f @ threshold=%.2f  P=%.3f R=%.3f\n",
                best_a.f1, best_a.threshold, best_a.precision, best_a.recall);
    std::printf("\nwrote %s/per_binary.csv, %s/sweep.csv, %s/summary.json\n",
                a.out_dir.string().c_str(), a.out_dir.string().c_str(),
                a.out_dir.string().c_str());
    return 0;
}
