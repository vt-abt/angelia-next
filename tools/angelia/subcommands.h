#pragma once

// One header, one declaration per subcommand. Each tool's file exposes
// a matching function; the dispatcher in tools/angelia/main.cpp hands
// argv (with the subcommand's name as argv[0]) to whichever fires.
//
// All subcommand entries are plain C++ free functions at global scope
// — each tool's main.cpp defines its own, and the dispatcher's function-
// pointer table wires them by name. No `extern "C"` — declarations and
// definitions share the same linkage.

int angelia_cli_run_bench          (int argc, char** argv);
int angelia_cli_run_collect        (int argc, char** argv);

int angelia_cli_run_mem_id         (int argc, char** argv);
int angelia_cli_run_pdb_offsets    (int argc, char** argv);
int angelia_cli_run_gen_synth_dump (int argc, char** argv);
int angelia_cli_run_sys_snapshot   (int argc, char** argv);
int angelia_cli_run_mem_analyze    (int argc, char** argv);

int angelia_cli_run_score          (int argc, char** argv);
int angelia_cli_run_behavior       (int argc, char** argv);

int angelia_cli_run_capture        (int argc, char** argv);
int angelia_cli_run_analyze        (int argc, char** argv);
int angelia_cli_run_classify       (int argc, char** argv);
int angelia_cli_run_writeup        (int argc, char** argv);

int angelia_cli_run_report         (int argc, char** argv);
int angelia_cli_run_eval           (int argc, char** argv);
int angelia_cli_run_case           (int argc, char** argv);
