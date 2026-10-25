find_package(nlohmann_json CONFIG REQUIRED)

add_library(angelia_memforensics STATIC
    DumpIdentify.cpp
    PdbTypeResolver.cpp
    PhysicalMemoryReader.cpp
    PageTableWalker.cpp
    KernelStructureCache.cpp
    ActiveProcessWalker.cpp
    LiveProcessSnapshot.cpp
    ProcessInventory.cpp)

target_link_libraries(angelia_memforensics
    PUBLIC  angelia_common nlohmann_json::nlohmann_json
    PRIVATE dbghelp ntdll shell32)

# Stage the Windows Kits' dbghelp + symsrv next to any exe that will use
# the resolver. The system dbghelp.dll ships without a companion
# symsrv.dll, so symbol-server URLs are silently ignored unless we
# supply both. LoadLibrary picks up the exe-dir copy first.
if(WIN32)
    set(_dbg_dirs
        "$ENV{ProgramFiles\(x86\)}/Windows Kits/10/Debuggers/x64"
        "$ENV{ProgramFiles}/Windows Kits/10/Debuggers/x64")
    foreach(_d IN LISTS _dbg_dirs)
        if(EXISTS "${_d}/symsrv.dll" AND EXISTS "${_d}/dbghelp.dll")
            message(STATUS "Staging dbghelp+symsrv from ${_d}")
            configure_file("${_d}/dbghelp.dll"
                "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/dbghelp.dll" COPYONLY)
            configure_file("${_d}/symsrv.dll"
                "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/symsrv.dll" COPYONLY)
            break()
        endif()
    endforeach()
endif()
