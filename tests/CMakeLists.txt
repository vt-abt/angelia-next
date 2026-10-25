add_executable(common_tests
    ObjectPool_test.cpp
    MpmcQueue_test.cpp
    SqliteWriter_test.cpp
    DumpIdentify_test.cpp
    PageTableWalker_test.cpp
    ActiveProcessWalker_test.cpp
    Entropy_test.cpp
    BehavioralScorer_test.cpp)
target_sources(common_tests PRIVATE ProviderEventKinds_test.cpp)

target_link_libraries(common_tests PRIVATE
    angelia_collector
    angelia_common
    angelia_memforensics
    angelia_riskscore
    GTest::gtest_main)

include(GoogleTest)
gtest_discover_tests(common_tests DISCOVERY_TIMEOUT 30)

find_program(ANGELIA_PWSH NAMES pwsh powershell.exe
    PATHS "$ENV{SystemRoot}/System32/WindowsPowerShell/v1.0")
find_program(ANGELIA_PYTHON NAMES python python3)
if(ANGELIA_PWSH AND ANGELIA_PYTHON)
    add_test(NAME CaseWorkbench.Smoke
        COMMAND ${ANGELIA_PWSH} -NoProfile -ExecutionPolicy Bypass
                -File ${CMAKE_CURRENT_SOURCE_DIR}/case_smoke.ps1)
    set_tests_properties(CaseWorkbench.Smoke PROPERTIES
        ENVIRONMENT "ANGELIA_PYTHON=${ANGELIA_PYTHON}")
endif()

if(ANGELIA_PWSH)
    add_test(NAME CrashCase.Smoke
        COMMAND ${ANGELIA_PWSH} -NoProfile -ExecutionPolicy Bypass
                -File ${CMAKE_CURRENT_SOURCE_DIR}/crash_case.ps1)
endif()

if(ANGELIA_PYTHON)
    add_test(NAME MemoryValidation.Compare
        COMMAND ${ANGELIA_PYTHON} ${CMAKE_CURRENT_SOURCE_DIR}/memory_compare_test.py)
endif()
