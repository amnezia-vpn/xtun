add_executable(tunnel_up tunnel_up.c)
target_link_libraries(tunnel_up PRIVATE xtun)

if(WIN32)
    find_file(GOXTUN_DLL libgoxtun.dll PATH_SUFFIXES bin)
    find_file(WINTUN_DLL wintun.dll PATH_SUFFIXES bin)

    if(GOXTUN_DLL AND WINTUN_DLL)
        add_custom_command(TARGET tunnel_up POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    ${GOXTUN_DLL} ${WINTUN_DLL} $<TARGET_FILE_DIR:tunnel_up>)
    else()
        message(WARNING
            "libgoxtun.dll / wintun.dll not found. Pass -DGOXTUN_DLL=... -DWINTUN_DLL=..., "
            "or copy them next to tunnel_up manually.")
    endif()
endif()
