find_package(go REQUIRED)

set(GOXTUN_SRC ${CMAKE_CURRENT_LIST_DIR}/src)
set(GOXTUN_OUT ${CMAKE_CURRENT_BINARY_DIR})

if(WIN32 OR ANDROID)
    set(GOXTUN_SHARED ON)
else()
    option(GOXTUN_SHARED "Build goxtun as a shared library" OFF)
endif()

set(_goos_Linux   linux)
set(_goos_Android android)
set(_goos_Windows windows)
set(_goos_Darwin  darwin)
set(_goos_iOS     ios)
set(GOOS ${_goos_${CMAKE_SYSTEM_NAME}})
if(NOT GOOS)
    message(FATAL_ERROR "goxtun: unsupported system '${CMAKE_SYSTEM_NAME}'")
endif()

function(goxtun_goarch out arch)
    string(TOLOWER "${arch}" arch)
    if(arch MATCHES "^(x86_64|amd64)$")
        set(_r amd64)
    elseif(arch MATCHES "^(aarch64|arm64|armv8|arm64-v8a)$")
        set(_r arm64)
    elseif(arch MATCHES "^(armv7|armv7-a|armeabi-v7a)$")
        set(_r arm)
    elseif(arch MATCHES "^(x86|i[3-6]86)$")
        set(_r 386)
    else()
        message(FATAL_ERROR "goxtun: unsupported arch '${arch}'")
    endif()
    set(${out} ${_r} PARENT_SCOPE)
endfunction()

if(APPLE AND CMAKE_OSX_ARCHITECTURES)
    set(_archs ${CMAKE_OSX_ARCHITECTURES})
elseif(ANDROID)
    set(_archs ${CMAKE_ANDROID_ARCH_ABI})
else()
    set(_archs ${CMAKE_SYSTEM_PROCESSOR})
endif()

if(WIN32)
    find_program(GOXTUN_CC gcc REQUIRED)
    find_program(GENDEF gendef REQUIRED)
    find_program(DLLTOOL dlltool REQUIRED)
else()
    set(GOXTUN_CC ${CMAKE_C_COMPILER})
endif()

set(_cflags)
if(CMAKE_C_COMPILER_TARGET)
    list(APPEND _cflags --target=${CMAKE_C_COMPILER_TARGET})
endif()
if(CMAKE_SYSROOT)
    list(APPEND _cflags --sysroot=${CMAKE_SYSROOT})
endif()
if(APPLE)
    set(_sdk_path ${CMAKE_OSX_SYSROOT})
    if(NOT IS_ABSOLUTE "${_sdk_path}")
        if(_sdk_path)
            set(_xcrun_sdk --sdk ${_sdk_path})
        endif()
        execute_process(
            COMMAND xcrun ${_xcrun_sdk} --show-sdk-path
            OUTPUT_VARIABLE _sdk_path
            OUTPUT_STRIP_TRAILING_WHITESPACE
            COMMAND_ERROR_IS_FATAL ANY)
    endif()
    list(APPEND _cflags ${CMAKE_C_SYSROOT_FLAG} ${_sdk_path})
    if(CMAKE_OSX_DEPLOYMENT_TARGET)
        list(APPEND _cflags ${CMAKE_C_OSX_DEPLOYMENT_TARGET_FLAG}${CMAKE_OSX_DEPLOYMENT_TARGET})
    endif()
endif()


set(_go_env
    CGO_ENABLED=1
    GOOS=${GOOS}
    CC=${GOXTUN_CC}
    GOPATH=${GOXTUN_OUT}/go
    GOMODCACHE=${GOXTUN_OUT}/go/pkg/mod
    GOCACHE=${GOXTUN_OUT}/go-cache
)

set(_go_env_mods)
if(WIN32)
    cmake_path(GET GOXTUN_CC PARENT_PATH _cc_dir)
    set(_go_env_mods --modify "PATH=path_list_prepend:${_cc_dir}")
endif()

set(_ldflags -w)
if(GOXTUN_SHARED)
    set(_buildmode c-shared)
    set(_suffix ${CMAKE_SHARED_LIBRARY_SUFFIX})
    if(APPLE)
        string(APPEND _ldflags " -extldflags=-Wl,-install_name,@rpath/libgoxtun.dylib")
    elseif(NOT WIN32)
        string(APPEND _ldflags " -extldflags=-Wl,-soname,libgoxtun${_suffix}")
    endif()
else()
    set(_buildmode c-archive)
    set(_suffix .a)
endif()

file(GLOB_RECURSE _go_sources CONFIGURE_DEPENDS ${GOXTUN_SRC}/*.go)
list(APPEND _go_sources ${GOXTUN_SRC}/go.mod ${GOXTUN_SRC}/go.sum)

set(_slices)
foreach(_arch IN LISTS _archs)
    goxtun_goarch(_goarch ${_arch})
    set(_arch_flags ${_cflags})
    if(APPLE)
        list(APPEND _arch_flags -arch ${_arch})
    endif()
    list(JOIN _arch_flags " " _arch_flags)

    set(_out ${GOXTUN_OUT}/${_arch}/libgoxtun${_suffix})
    add_custom_command(
        OUTPUT ${_out} ${GOXTUN_OUT}/${_arch}/libgoxtun.h
        COMMAND ${CMAKE_COMMAND} -E env ${_go_env_mods} ${_go_env}
                GOARCH=${_goarch} GOARM=7
                "CGO_CFLAGS=${_arch_flags}" "CGO_LDFLAGS=${_arch_flags}"
                $<TARGET_FILE:golang::go> build -trimpath "-ldflags=${_ldflags}"
                    -buildmode=${_buildmode} -o ${_out} .
        WORKING_DIRECTORY ${GOXTUN_SRC}
        DEPENDS ${_go_sources}
        COMMENT "Building goxtun (${GOOS}/${_goarch}, ${_buildmode})"
        VERBATIM)
    list(APPEND _slices ${_out})
endforeach()

set(GOXTUN_LIBRARY ${GOXTUN_OUT}/libgoxtun${_suffix})
set(GOXTUN_HEADER  ${GOXTUN_OUT}/libgoxtun.h)
list(GET _archs 0 _first)
if(APPLE)
    set(_merge lipo -create -output ${GOXTUN_LIBRARY} ${_slices})
else()
    set(_merge ${CMAKE_COMMAND} -E copy ${_slices} ${GOXTUN_LIBRARY})
endif()
add_custom_command(
    OUTPUT ${GOXTUN_LIBRARY} ${GOXTUN_HEADER}
    COMMAND ${_merge}
    COMMAND ${CMAKE_COMMAND} -E copy ${GOXTUN_OUT}/${_first}/libgoxtun.h ${GOXTUN_HEADER}
    DEPENDS ${_slices}
    VERBATIM)
set(_outputs ${GOXTUN_LIBRARY} ${GOXTUN_HEADER})

if(WIN32)
    set(GOXTUN_IMPLIB ${GOXTUN_OUT}/libgoxtun.lib)
    add_custom_command(
        OUTPUT ${GOXTUN_IMPLIB}
        COMMAND ${GENDEF} libgoxtun.dll
        COMMAND ${DLLTOOL} -d libgoxtun.def -l libgoxtun.lib -D libgoxtun.dll
        COMMAND ${CMAKE_COMMAND} -E rm -f libgoxtun.def
        WORKING_DIRECTORY ${GOXTUN_OUT}
        DEPENDS ${GOXTUN_LIBRARY}
        VERBATIM)
    list(APPEND _outputs ${GOXTUN_IMPLIB})
endif()

add_custom_target(goxtun_build DEPENDS ${_outputs})

if(GOXTUN_SHARED)
    add_library(goxtun SHARED IMPORTED GLOBAL)
else()
    add_library(goxtun STATIC IMPORTED GLOBAL)
endif()
set_target_properties(goxtun PROPERTIES
    IMPORTED_LOCATION ${GOXTUN_LIBRARY}
    INTERFACE_INCLUDE_DIRECTORIES ${GOXTUN_OUT})
if(WIN32)
    set_target_properties(goxtun PROPERTIES IMPORTED_IMPLIB ${GOXTUN_IMPLIB})
endif()
if(NOT GOXTUN_SHARED)
    # Golang requires
    find_package(Threads REQUIRED)
    target_link_libraries(goxtun INTERFACE Threads::Threads ${CMAKE_DL_LIBS})
    if(APPLE)
        target_link_libraries(goxtun INTERFACE "-framework CoreFoundation" "-framework Security")
    endif()
endif()
add_dependencies(goxtun goxtun_build)

if(WIN32)
    install(FILES ${GOXTUN_LIBRARY} DESTINATION bin)
    install(FILES ${GOXTUN_IMPLIB} DESTINATION lib)
else()
    install(FILES ${GOXTUN_LIBRARY} DESTINATION lib)
endif()
