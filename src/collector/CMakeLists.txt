add_library(angelia_collector STATIC
    SqliteWriter.cpp)

target_link_libraries(angelia_collector
    PUBLIC  angelia_common)

if(_angelia_krabsetw_ok)
    target_sources(angelia_collector PRIVATE KrabsConsumer.cpp)
    target_include_directories(angelia_collector PUBLIC ${KRABSETW_INCLUDE_DIR})
    target_link_libraries(angelia_collector PUBLIC tdh)
    target_compile_definitions(angelia_collector PUBLIC ANGELIA_HAVE_KRABSETW=1)
endif()
