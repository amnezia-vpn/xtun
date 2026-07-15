cmake_minimum_required(VERSION 3.25.0)

include(${CMAKE_SOURCE_DIR}/cmake/cmake-conan/conan_bootstrap.cmake)

set(CMAKE_PROJECT_TOP_LEVEL_INCLUDES
    ${CMAKE_SOURCE_DIR}/cmake/cmake-conan/conan_provider.cmake
    CACHE STRING "" FORCE)

project(xtun)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(goxtun REQUIRED)
find_package(Threads REQUIRED)

add_library(${PROJECT_NAME}
    ${CMAKE_CURRENT_LIST_DIR}/src/proxy.cpp
    ${CMAKE_CURRENT_LIST_DIR}/src/tunnel.cpp
)
target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_17)
target_include_directories(${PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}
)
target_link_libraries(${PROJECT_NAME} PUBLIC amnezia::goxtun Threads::Threads)

if(WIN32)
    find_package(wintun REQUIRED)
    target_link_libraries(${PROJECT_NAME} PUBLIC amnezia::wintun)
    target_compile_definitions(${PROJECT_NAME} PUBLIC WIN32_LEAN_AND_MEAN NOMINMAX)
endif()

if(PROJECT_IS_TOP_LEVEL)
    enable_testing()
    add_subdirectory(tests)
endif()
