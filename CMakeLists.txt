cmake_minimum_required(VERSION 3.25)

# Root CMakeLists — the toolchain and generator come from CMakePresets.json.
project(angelia
    VERSION 0.4.0
    DESCRIPTION "Windows investigation workbench"
    LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

if(MSVC)
    # /W4 warnings-as-errors; /permissive- + /Zc:__cplusplus for standards conformance.
    # /EHsc: standard C++ exceptions (we still use __try/__except in the crash-triage
    # module, gated on MSVC-specific TUs).
    add_compile_options(
        /W4 /WX /permissive- /Zc:__cplusplus /Zc:preprocessor
        /EHsc /utf-8 /MP
        /wd4324   # structure padded due to alignment specifier (Cell/atomic pos)
        /wd4127   # conditional expression is constant (fires inside SDK headers)
        /DUNICODE /D_UNICODE
        /D_WIN32_WINNT=0x0A00 /DWINVER=0x0A00 /DNOMINMAX /DWIN32_LEAN_AND_MEAN)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
    # Every release build has full mitigations. Vulnerable-corpus targets in
    # Stage 4 opt out per-target — see src/crashtriage/CMakeLists.txt (Stage 4).
    add_link_options(/DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA)
endif()

option(ANGELIA_WITH_KRABSETW "Enable KrabsETW-backed live collector" ON)
option(ANGELIA_BUILD_TESTS   "Build gtest suite"                     ON)
option(ANGELIA_BUILD_BENCH   "Build load-driver benchmarks"          ON)

find_package(fmt         CONFIG REQUIRED)
find_package(spdlog      CONFIG REQUIRED)
# sqlite3 is vendored — see third_party/sqlite-amalgamation.
add_subdirectory(third_party/sqlite-amalgamation)
if(ANGELIA_BUILD_TESTS)
    find_package(GTest   CONFIG REQUIRED)
    enable_testing()
endif()
if(ANGELIA_BUILD_BENCH)
    find_package(benchmark CONFIG REQUIRED)
endif()

set(_angelia_krabsetw_ok FALSE)
if(ANGELIA_WITH_KRABSETW)
    # KrabsETW is header-only; the vcpkg port exports the include dir via
    # find_path rather than a CMake config target.
    find_path(KRABSETW_INCLUDE_DIR "krabs.hpp")
    if(KRABSETW_INCLUDE_DIR)
        message(STATUS "KrabsETW headers: ${KRABSETW_INCLUDE_DIR}")
        set(_angelia_krabsetw_ok TRUE)
    else()
        # Don't rewrite the user-facing option — that turns a transient
        # detection failure into a permanent cache-sticky OFF. Just skip
        # the dependent targets for this configure.
        message(WARNING "krabs.hpp not found on include path; live collector "
                        "disabled for this configure. Delete build/default/CMakeCache.txt "
                        "and retry once the header is available.")
    endif()
endif()

find_package(Zydis CONFIG QUIET)
if(NOT Zydis_FOUND)
    message(WARNING "Zydis not installed; P0.5 analyzer disabled. Add \"zydis\" to vcpkg.json and re-run configure.")
endif()

add_subdirectory(src/common)
add_subdirectory(src/collector)
add_subdirectory(src/memforensics)
add_subdirectory(src/crashtriage)
add_subdirectory(src/riskscore)

# One binary: angelia.exe. Every previous tool is now a subcommand
# inside it (tools/angelia). Zydis and KrabsETW must be present at
# build time — the pipeline is meant to be shipped as a single .exe
# with all subcommands available.
if(NOT Zydis_FOUND)
    message(FATAL_ERROR "Zydis is required for the consolidated angelia.exe. "
                        "Add 'zydis' to vcpkg.json and reconfigure.")
endif()
if(NOT _angelia_krabsetw_ok)
    message(FATAL_ERROR "KrabsETW is required for the consolidated angelia.exe. "
                        "Ensure 'krabsetw' is installed via vcpkg and reconfigure.")
endif()
add_subdirectory(tools/angelia)

if(ANGELIA_BUILD_TESTS)
    add_subdirectory(tests)
endif()
