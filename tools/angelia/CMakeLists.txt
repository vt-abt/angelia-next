# One binary that pulls in every subcommand's TU. The old per-tool
# CMakeLists files were deleted — each tool is now just a source file.

add_executable(angelia
    main.cpp
    # Collector
    ../p01_bench/main.cpp
    ../p01_kernel_smoke/main.cpp
    # Memory forensics
    ../mem_id/main.cpp
    ../pdb_offsets/main.cpp
    ../gen_synthetic_dump/main.cpp
    ../sys_snapshot/main.cpp
    ../mem_analyze/main.cpp
    # Risk scoring
    ../pe_score/main.cpp
    ../behavior_score/main.cpp
    # Crash triage
    ../p04_capture/main.cpp
    ../p05_analyze/main.cpp
    ../p06_classify/main.cpp
    ../p07_writeup/main.cpp
    # Integration
    ../incident_report/main.cpp
    # Evaluation
    ../eval_static/main.cpp)
target_sources(angelia PRIVATE ../case_workbench/main.cpp)

find_package(pugixml CONFIG REQUIRED)

target_include_directories(angelia PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/..)

target_link_libraries(angelia PRIVATE
    angelia_collector
    angelia_common
    angelia_memforensics
    angelia_crashtriage
    angelia_riskscore
    dbghelp
    winhttp
    Zydis::Zydis)
target_link_libraries(angelia PRIVATE pugixml::pugixml wevtapi bcrypt)

# Every subcommand's main.cpp declares its own translation-unit-local
# helpers in anonymous namespaces, so folding them into one binary is
# just linking. No global-symbol collisions expected.
