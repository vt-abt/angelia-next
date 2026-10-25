// p06_classify — reads an analyzed crash artifact (must contain the
// `analysis` block written by p05_analyze), runs the MSEC classifier,
// writes the artifact back with a `verdict` block.
//
// Usage:
//   p06_classify <artifact.json> [--out <path>]

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string_view>

#include "crashtriage/CrashArtifact.h"
#include "crashtriage/MsecClassifier.h"

namespace ac = angelia::crashtriage;

int angelia_cli_run_classify(int argc, char** argv) {
    std::filesystem::path in_path, out_path;
    for (int i = 1; i < argc; ++i) {
        std::string_view k = argv[i];
        if      (k == "--out" && i + 1 < argc) out_path = argv[++i];
        else if (k[0] != '-')                  in_path  = std::string(k);
        else { std::fprintf(stderr, "unknown arg: %.*s\n", (int)k.size(), k.data()); return 2; }
    }
    if (in_path.empty()) {
        std::fprintf(stderr, "usage: p06_classify <artifact.json> [--out <path>]\n");
        return 2;
    }
    if (out_path.empty()) out_path = in_path;

    std::ifstream f(in_path);
    if (!f) { std::fprintf(stderr, "cannot open %s\n", in_path.string().c_str()); return 1; }
    std::stringstream ss; ss << f.rdbuf();

    ac::CrashArtifact a;
    std::string err;
    if (!ac::from_json_str(ss.str(), a, err)) {
        std::fprintf(stderr, "parse: %s\n", err.c_str());
        return 1;
    }
    if (!a.analysis) {
        std::fprintf(stderr, "no analysis block on artifact; run p05_analyze first\n");
        return 1;
    }

    const auto v = ac::classify(a);

    std::ofstream out(out_path, std::ios::binary | std::ios::trunc);
    if (!out) { std::fprintf(stderr, "cannot write %s\n", out_path.string().c_str()); return 1; }
    auto js = ac::to_json(a);
    out.write(js.data(), static_cast<std::streamsize>(js.size()));

    std::printf("classified: %s\n", out_path.string().c_str());
    std::printf("  bucket     : %s\n", ac::to_string(v.bucket));
    std::printf("  confidence : %.2f\n", v.confidence);
    std::printf("  rationale  : %s\n", v.rationale.c_str());
    if (!v.evidence_slugs.empty()) {
        std::printf("  supporting :\n");
        for (const auto& s : v.evidence_slugs) std::printf("    - %s\n", s.c_str());
    }
    return 0;
}
