cmake_minimum_required(VERSION 3.25.0)

# We compile against c++20, but remain runnable against c++17
# Do NOT use any runtime-based features like:
#   <format>, <jthread>, <latch>, <barrier>, <syncstream>,
#   <chrono> tz/calendar, and others.
SET(CMAKE_CXX_STANDARD 20)
SET(CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(${CMAKE_SOURCE_DIR}/cmake/cmake-conan/conan_bootstrap.cmake)
set(CMAKE_PROJECT_TOP_LEVEL_INCLUDES
    ${CMAKE_CURRENT_LIST_DIR}/cmake/recipes_bootstrap.cmake
    ${CMAKE_SOURCE_DIR}/cmake/cmake-conan/conan_provider.cmake
    CACHE STRING "" FORCE)

project(xtun)

find_package(goxtun REQUIRED)
find_package(Threads REQUIRED)

add_library(${PROJECT_NAME}
    ${CMAKE_CURRENT_LIST_DIR}/src/proto/awg.cpp
    ${CMAKE_CURRENT_LIST_DIR}/src/proto/awg_conf.cpp
    ${CMAKE_CURRENT_LIST_DIR}/src/proxy.cpp
    ${CMAKE_CURRENT_LIST_DIR}/src/router.cpp
    ${CMAKE_CURRENT_LIST_DIR}/src/tunnel.cpp
)
target_include_directories(${PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/src
    ${CMAKE_CURRENT_LIST_DIR}
)
target_link_libraries(${PROJECT_NAME} PUBLIC amnezia::goxtun Threads::Threads)

if(WIN32)
    find_package(wintun REQUIRED)
    target_link_libraries(${PROJECT_NAME} PUBLIC amnezia::wintun)
    target_link_libraries(${PROJECT_NAME} PRIVATE iphlpapi ws2_32)
    target_compile_definitions(${PROJECT_NAME} PUBLIC WIN32_LEAN_AND_MEAN NOMINMAX)
endif()

if(LINUX)
    find_package(libsystemd REQUIRED)
    target_link_libraries(${PROJECT_NAME} PRIVATE libsystemd::libsystemd)
endif()

if(PROJECT_IS_TOP_LEVEL)
    enable_testing()
    add_subdirectory(tests)
endif()
