cmake_minimum_required(VERSION 3.20)

project(awgconfig C)

set(UPSTREAM ${CMAKE_CURRENT_LIST_DIR}/upstream/src)

if(NOT DEFINED AWG_RUNSTATEDIR)
    set(AWG_RUNSTATEDIR "/var/run")
endif()

add_library(awgconfig STATIC
    ${CMAKE_CURRENT_LIST_DIR}/awgconfig.c
    ${UPSTREAM}/config.c
    ${UPSTREAM}/encoding.c
)

set_target_properties(awgconfig PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_compile_definitions(awgconfig PRIVATE RUNSTATEDIR="${AWG_RUNSTATEDIR}")

target_include_directories(awgconfig PUBLIC ${CMAKE_CURRENT_LIST_DIR})
target_include_directories(awgconfig PRIVATE ${UPSTREAM})

install(TARGETS awgconfig ARCHIVE DESTINATION lib)
install(FILES ${CMAKE_CURRENT_LIST_DIR}/awgconfig.h DESTINATION include)
