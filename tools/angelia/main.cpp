// angelia — single-binary entry point.
//
// One .exe, sixteen subcommands. Every subcommand's argv[0] is
// rewritten to its own name so downstream getopt-style logic keeps
// working unchanged.
//
//   angelia <subcommand> [args...]
//   angelia --help
//   angelia --version
//
// Group headings in --help follow the four-component structure so a
// reader who's opened this from a fresh install can find their way.

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "angelia/subcommands.h"

namespace {

using Handler = int(*)(int, char**);

struct Sub {
    const char* name;
    const char* group;
    const char* summary;
    Handler     fn;
};

// Order defines --help output order. Keep grouped so a reader sees the
// natural pipeline flow (collect → memory forensics → risk → triage →
// integration → eval).
constexpr Sub kSubs[] = {
    {"bench",          "Collector",       "synthetic 1M-event pipeline load test",       angelia_cli_run_bench},
    {"collect",        "Collector",       "live kernel ETW collection (elevated)",       angelia_cli_run_collect},
    {"case",           "Investigation",   "import evidence and query a linked timeline", angelia_cli_run_case},

    {"mem-id",         "Memory forensics","identify a memory-dump format",               angelia_cli_run_mem_id},
    {"pdb-offsets",    "Memory forensics","resolve struct-member offsets from a PDB",    angelia_cli_run_pdb_offsets},
    {"gen-synth-dump", "Memory forensics","generate a synthetic PAGEDU64 (for tests)",   angelia_cli_run_gen_synth_dump},
    {"sys-snapshot",   "Memory forensics","capture the live process list to JSON",       angelia_cli_run_sys_snapshot},
    {"mem-analyze",    "Memory forensics","process inventory from a dump + snapshot",    angelia_cli_run_mem_analyze},

    {"score",          "Risk scoring",    "static PE risk score (entropy + imports)",    angelia_cli_run_score},
    {"behavior",       "Risk scoring",    "behavioural risk score from a timeline DB",   angelia_cli_run_behavior},

    {"capture",        "Crash triage",    "parent-debugger crash capture",               angelia_cli_run_capture},
    {"analyze",        "Crash triage",    "add Zydis + pattern evidence to an artifact", angelia_cli_run_analyze},
    {"classify",       "Crash triage",    "add MSEC verdict to an analyzed artifact",    angelia_cli_run_classify},
    {"writeup",        "Crash triage",    "LLM-authored plain-English writeup",          angelia_cli_run_writeup},

    {"report",         "Integration",     "compose a per-incident HTML report",          angelia_cli_run_report},

    {"eval",           "Evaluation",      "precision/recall over a labeled corpus",      angelia_cli_run_eval},
};

int print_usage() {
    std::printf(
        "angelia — Windows incident-triage pipeline\n"
        "\n"
        "Usage:\n"
        "  angelia <subcommand> [args...]\n"
        "  angelia --help | -h\n"
        "  angelia --version | -v\n"
        "\n");
    const char* current_group = nullptr;
    for (const auto& s : kSubs) {
        if (current_group == nullptr || std::strcmp(current_group, s.group) != 0) {
            std::printf("%s:\n", s.group);
            current_group = s.group;
        }
        std::printf("  %-16s %s\n", s.name, s.summary);
    }
    std::printf("\nRun `angelia <subcommand> --help` for per-subcommand args.\n");
    return 0;
}

int print_version() {
    std::printf("angelia 0.4.0\n"
                "Windows investigation workbench.\n");
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) return print_usage();

    const std::string cmd = argv[1];
    if (cmd == "-h" || cmd == "--help")    return print_usage();
    if (cmd == "-v" || cmd == "--version") return print_version();

    for (const auto& s : kSubs) {
        if (cmd == s.name) {
            // Rewrite argv so the subcommand sees its own name as argv[0]
            // and its own args starting at argv[1].
            std::vector<char*> fwd;
            fwd.reserve(argc);
            fwd.push_back(const_cast<char*>(s.name));
            for (int i = 2; i < argc; ++i) fwd.push_back(argv[i]);
            return s.fn(static_cast<int>(fwd.size()), fwd.data());
        }
    }
    std::fprintf(stderr, "angelia: unknown subcommand '%s'\n\n", cmd.c_str());
    print_usage();
    return 2;
}
