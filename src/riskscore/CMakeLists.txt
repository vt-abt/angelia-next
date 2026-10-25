add_library(angelia_riskscore STATIC
    Entropy.cpp
    PeImage.cpp
    ImportScanner.cpp
    StaticScorer.cpp
    BehavioralScorer.cpp)

target_link_libraries(angelia_riskscore
    PUBLIC angelia_common angelia_collector)

# --- Test target: a benign binary that IMPORTS the injection triad.
# Used to prove the scanner's rules actually fire when the shape is
# present. Kept in-tree so the signal check reproduces from source.
add_executable(test_injection_triad test_injection_triad.c)
target_compile_options(test_injection_triad PRIVATE /W3 /WX-)
set_target_properties(test_injection_triad PROPERTIES
    MSVC_RUNTIME_LIBRARY "MultiThreadedDLL")
