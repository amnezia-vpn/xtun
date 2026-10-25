find_package(GTest REQUIRED)
include(GoogleTest)

add_executable(xtun_cpp_fakextun_test test_fakextun.cpp)
target_include_directories(xtun_cpp_fakextun_test PRIVATE
    ../include
    ${CMAKE_SOURCE_DIR}/include
)
target_link_libraries(xtun_cpp_fakextun_test PRIVATE GTest::gtest GTest::gtest_main)
gtest_discover_tests(xtun_cpp_fakextun_test TEST_PREFIX "xtun-cpp.")
