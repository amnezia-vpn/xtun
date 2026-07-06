cmake_minimum_required(VERSION 3.25.0)

include(${CMAKE_SOURCE_DIR}/cmake/cmake-conan/conan_bootstrap.cmake)

set(CMAKE_PROJECT_TOP_LEVEL_INCLUDES
    ${CMAKE_SOURCE_DIR}/cmake/cmake-conan/conan_provider.cmake
    CACHE STRING "" FORCE)

project(xtun)

find_package(goxtun REQUIRED)

add_library(${PROJECT_NAME}
    ${CMAKE_CURRENT_LIST_DIR}/src/proxy.cpp
    ${CMAKE_CURRENT_LIST_DIR}/src/tunnel.cpp
)
target_include_directories(${PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}
)
target_link_libraries(${PROJECT_NAME} PUBLIC amnezia::goxtun)
