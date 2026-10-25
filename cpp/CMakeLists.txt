target_include_directories(${PROJECT_NAME} INTERFACE
    ${CMAKE_CURRENT_LIST_DIR}/include
)
install(FILES ${CMAKE_CURRENT_LIST_DIR}/include/xtun.hpp DESTINATION include)

if(BUILD_TESTS AND NOT CMAKE_CROSSCOMPILING)
    add_subdirectory(tests)
endif()
