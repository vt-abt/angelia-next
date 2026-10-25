add_library(angelia_common STATIC
    Sqlite.cpp
    Logging.cpp)

target_include_directories(angelia_common PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/..)

target_link_libraries(angelia_common
    PUBLIC
        fmt::fmt
        spdlog::spdlog
        sqlite3_amalgamation)

target_compile_features(angelia_common PUBLIC cxx_std_20)
