cmake_minimum_required(VERSION 3.25.0)

project(xtun)

add_library(${PROJECT_NAME}
    ${CMAKE_CURRENT_LIST_DIR}/src/proxy.cpp
    ${CMAKE_CURRENT_LIST_DIR}/src/tunnel.cpp
)
target_include_directories(${PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}
)
