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

if(WIN32)
    find_package(wintun REQUIRED)
    target_link_libraries(${PROJECT_NAME} PUBLIC amnezia::wintun)
    target_compile_definitions(${PROJECT_NAME} PUBLIC WIN32_LEAN_AND_MEAN NOMINMAX)
endif()

if(PROJECT_IS_TOP_LEVEL)
    add_subdirectory(tests)
endif()
