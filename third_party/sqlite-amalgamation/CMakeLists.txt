# Vendored SQLite amalgamation (v3.53.4). Bundled because the sqlite3
# vcpkg port trips on the newer Windows SDK's rc.exe under our toolchain,
# and there is no upside to depending on vcpkg for a single .c file.

add_library(sqlite3_amalgamation STATIC sqlite3.c)
target_include_directories(sqlite3_amalgamation PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_definitions(sqlite3_amalgamation PUBLIC
    SQLITE_ENABLE_JSON1=1
    SQLITE_ENABLE_STAT4=1
    SQLITE_THREADSAFE=1
    SQLITE_DEFAULT_MEMSTATUS=0
    SQLITE_OMIT_LOAD_EXTENSION=1)

if(MSVC)
    # Vendor code — disable warnings-as-errors and drop /W4 down to /W3.
    # /WX- explicitly clears any inherited /WX.
    set_source_files_properties(sqlite3.c PROPERTIES
        COMPILE_FLAGS "/W3 /WX- /wd4996 /wd4244 /wd4267 /wd4018 /wd4146 /wd4200 /wd4204 /wd4232 /wd4324 /wd4127")
endif()
