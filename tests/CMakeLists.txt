find_package(GTest REQUIRED)
include(GoogleTest)

set(XTUN_TEST_SOURCES
    awg_realtun_test.cpp
    awg_roundtrip_test.cpp
    awg_tunnel_test.cpp
    health_monitor_test.cpp
    health_monitored_io_test.cpp
    health_probe_test.cpp
    health_resolver_test.cpp
    health_scheduler_test.cpp
    health_verdict_test.cpp
    net_ip_test.cpp
    net_socket_test.cpp
    net_udp_test.cpp
    proxy_attach_test.cpp
    tunnel_contract_test.cpp
    tunnel_lifecycle_test.cpp
)

if(NOT WIN32)
    list(APPEND XTUN_TEST_SOURCES routing_test.cpp)
endif()

add_executable(xtun_tests ${XTUN_TEST_SOURCES})
target_link_libraries(xtun_tests PRIVATE xtun GTest::gtest GTest::gtest_main)
target_include_directories(xtun_tests PRIVATE ${CMAKE_SOURCE_DIR}/src)

if(WIN32)
    target_link_libraries(xtun_tests PRIVATE amnezia::wintun advapi32 iphlpapi)

    add_custom_command(TARGET xtun_tests POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                $<TARGET_RUNTIME_DLLS:xtun_tests> $<TARGET_FILE_DIR:xtun_tests>
        COMMAND_EXPAND_LISTS)

    get_target_property(_wintun_include amnezia::wintun INTERFACE_INCLUDE_DIRECTORIES)
    find_file(WINTUN_DLL wintun.dll HINTS ${_wintun_include} PATH_SUFFIXES ../bin bin)
    if(WINTUN_DLL)
        add_custom_command(TARGET xtun_tests POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    ${WINTUN_DLL} $<TARGET_FILE_DIR:xtun_tests>)
    else()
        message(WARNING "wintun.dll not found; copy it next to xtun_tests manually.")
    endif()
endif()

gtest_discover_tests(xtun_tests PROPERTIES TIMEOUT 30)
