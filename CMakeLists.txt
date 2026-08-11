cmake_minimum_required(VERSION 3.25.0)

include(${CMAKE_SOURCE_DIR}/cmake/cmake-conan/conan_bootstrap.cmake)

set(CMAKE_PROJECT_TOP_LEVEL_INCLUDES
    ${CMAKE_SOURCE_DIR}/cmake/cmake-conan/conan_provider.cmake
    CACHE STRING "" FORCE)

project(xtun)

if(PROJECT_IS_TOP_LEVEL)
    include(${CMAKE_CURRENT_LIST_DIR}/cmake/recipes_bootstrap.cmake)
endif()

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

# We compile against c++20, but remain runnable against c++17
# Do NOT use any runtime-based features like:
#   <format>, <jthread>, <latch>, <barrier>, <syncstream>,
#   <chrono> tz/calendar, and others.
target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_20)

if(WIN32)
    find_package(wintun REQUIRED)
    target_sources(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_LIST_DIR}/src/router_windows.cpp)
    target_link_libraries(${PROJECT_NAME} PUBLIC amnezia::wintun)
    target_link_libraries(${PROJECT_NAME} PRIVATE iphlpapi ws2_32)
    target_compile_definitions(${PROJECT_NAME} PUBLIC WIN32_LEAN_AND_MEAN NOMINMAX)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_sources(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_LIST_DIR}/src/router_linux.cpp)
    find_package(PkgConfig)
    if(PkgConfig_FOUND)
        pkg_check_modules(SYSTEMD libsystemd)
        if(SYSTEMD_FOUND)
            target_compile_definitions(${PROJECT_NAME} PRIVATE XTUN_HAVE_SYSTEMD)
            target_include_directories(${PROJECT_NAME} PRIVATE ${SYSTEMD_INCLUDE_DIRS})
            target_link_libraries(${PROJECT_NAME} PRIVATE ${SYSTEMD_LIBRARIES})
        endif()
    endif()
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    target_sources(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_LIST_DIR}/src/router_macos.cpp)
endif()

if(PROJECT_IS_TOP_LEVEL)
    enable_testing()
    add_subdirectory(tests)
endif()
