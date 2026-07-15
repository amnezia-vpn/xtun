find_package(GTest REQUIRED)
include(GoogleTest)

add_executable(xtun_tests
    tunnel_contract_test.cpp
    tunnel_lifecycle_test.cpp
)
target_link_libraries(xtun_tests PRIVATE xtun GTest::gtest GTest::gtest_main)

if(WIN32)
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

gtest_discover_tests(xtun_tests)
