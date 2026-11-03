find_package(GTest REQUIRED)
include(GoogleTest)

configure_file(data/ovpn_client.ovpn data/ovpn_client.ovpn COPYONLY NO_SOURCE_PERMISSIONS)

set(XTUN_TEST_SOURCES
    test_awaiting_io.cpp
    test_contract.cpp
    test_killswitch.cpp
    test_net_ip.cpp
    test_net_socket.cpp
    test_net_packet_builder.cpp
    test_ovpn.cpp
    test_proxy.cpp
    test_proxy_profile.cpp
    test_scenario.cpp
    test_socket_protection.cpp
    test_tunnel.cpp
)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT ANDROID)
    list(APPEND XTUN_TEST_SOURCES test_router_linux.cpp)
endif()

add_executable(xtun_tests ${XTUN_TEST_SOURCES})
target_link_libraries(xtun_tests PRIVATE xtun GTest::gtest GTest::gtest_main)
target_include_directories(xtun_tests PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_compile_definitions(xtun_tests PRIVATE
    XTUN_TEST_OVPN_CLIENT_PROFILE="${CMAKE_CURRENT_BINARY_DIR}/data/ovpn_client.ovpn"
    XTUN_TEST_SECRETS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/secrets")

if(WIN32)
    target_link_libraries(xtun_tests PRIVATE amnezia::wintun advapi32 iphlpapi fwpuclnt)

    add_custom_command(TARGET xtun_tests POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                $<TARGET_RUNTIME_DLLS:xtun_tests>
                "$<TARGET_PROPERTY:amnezia::wintun,INTERFACE_INCLUDE_DIRECTORIES>/../bin/wintun.dll"
                $<TARGET_FILE_DIR:xtun_tests>
        COMMAND_EXPAND_LISTS)
endif()

gtest_discover_tests(xtun_tests TEST_FILTER "Killswitch*" PROPERTIES TIMEOUT 30 RUN_SERIAL TRUE)
gtest_discover_tests(xtun_tests TEST_FILTER "-Killswitch*" PROPERTIES TIMEOUT 30)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT ANDROID)
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    find_program(XTUN_TEST_OPENVPN_EXECUTABLE NAMES openvpn REQUIRED)

    configure_file(ovpn_server.py ovpn_server.py COPYONLY NO_SOURCE_PERMISSIONS)

    add_executable(xtun_ovpn_session_tests test_ovpn_session.cpp ovpn_main.cpp)
    target_link_libraries(xtun_ovpn_session_tests PRIVATE xtun GTest::gtest)
    target_include_directories(xtun_ovpn_session_tests PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_compile_definitions(xtun_ovpn_session_tests PRIVATE
        XTUN_TEST_OVPN_CLIENT_PROFILE="${CMAKE_CURRENT_BINARY_DIR}/data/ovpn_client.ovpn"
        XTUN_TEST_PYTHON_EXECUTABLE="${Python3_EXECUTABLE}"
        XTUN_TEST_OVPN_SERVER_SCRIPT="${CMAKE_CURRENT_BINARY_DIR}/ovpn_server.py"
        XTUN_TEST_OPENVPN_EXECUTABLE="${XTUN_TEST_OPENVPN_EXECUTABLE}")
    gtest_discover_tests(xtun_ovpn_session_tests PROPERTIES TIMEOUT 30 SKIP_RETURN_CODE 77)
endif()
