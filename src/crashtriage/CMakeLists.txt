find_package(nlohmann_json CONFIG REQUIRED)

add_library(angelia_crashtriage STATIC
    CyclicPattern.cpp
    CrashArtifact.cpp
    MsecClassifier.cpp)

target_link_libraries(angelia_crashtriage
    PUBLIC angelia_common nlohmann_json::nlohmann_json)

# --- Vulnerable-corpus targets ---------------------------------------------
# Same source, three mitigation postures. The build injects /GS-, /GS-only,
# or full (/GS /guard:cf + /DYNAMICBASE /NXCOMPAT /GUARD:CF /HIGHENTROPYVA
# /CETCOMPAT). MSVC lets later /X:NO override earlier /X, which is how we
# undo the project-wide /DYNAMICBASE etc.

function(angelia_add_vuln_variant target_name src level)
    add_executable(${target_name} ${src})
    # Vendor-ish targets: warnings not errors, keep the /GS toggle honest.
    target_compile_options(${target_name} PRIVATE /W3 /WX-)
    set_target_properties(${target_name} PROPERTIES
        OUTPUT_NAME ${target_name}
        MSVC_RUNTIME_LIBRARY "MultiThreadedDLL")
    if(level STREQUAL "off")
        target_compile_options(${target_name} PRIVATE /GS-)
        target_link_options   (${target_name} PRIVATE
            /DYNAMICBASE:NO /NXCOMPAT:NO /HIGHENTROPYVA:NO)
        target_compile_definitions(${target_name} PRIVATE
            ANGELIA_VUL_MITIGATION_LEVEL="off")
    elseif(level STREQUAL "gs")
        target_compile_options(${target_name} PRIVATE /GS)
        target_link_options   (${target_name} PRIVATE
            /DYNAMICBASE:NO /NXCOMPAT:NO /HIGHENTROPYVA:NO)
        target_compile_definitions(${target_name} PRIVATE
            ANGELIA_VUL_MITIGATION_LEVEL="gs_only")
    elseif(level STREQUAL "full")
        target_compile_options(${target_name} PRIVATE /GS /guard:cf)
        target_link_options   (${target_name} PRIVATE
            /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA /GUARD:CF /CETCOMPAT)
        target_compile_definitions(${target_name} PRIVATE
            ANGELIA_VUL_MITIGATION_LEVEL="full")
    else()
        message(FATAL_ERROR "unknown mitigation level: ${level}")
    endif()
endfunction()

angelia_add_vuln_variant(vuln_stack_off  vuln_stack_strcpy.c off)
angelia_add_vuln_variant(vuln_stack_gs   vuln_stack_strcpy.c gs)
angelia_add_vuln_variant(vuln_stack_full vuln_stack_strcpy.c full)

angelia_add_vuln_variant(vuln_heap_off   vuln_heap_oob.c off)
angelia_add_vuln_variant(vuln_heap_gs    vuln_heap_oob.c gs)
angelia_add_vuln_variant(vuln_heap_full  vuln_heap_oob.c full)
