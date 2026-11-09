if (NOT CMAKE_HOST_APPLE)
    message(FATAL_ERROR "Swift bindings can only be built on a macOS host")
endif()

option(XTUN_SWIFT_SLICE "Internal: build a single Xtun.framework slice" OFF)
mark_as_advanced(XTUN_SWIFT_SLICE)

set(XTUN_IOS_DEPLOYMENT_TARGET "15.0" CACHE STRING "Minimum iOS version")
set(XTUN_MACOS_DEPLOYMENT_TARGET "12.0" CACHE STRING "Minimum macOS version")

set(_swift_sources
    ${CMAKE_CURRENT_LIST_DIR}/Sources/Xtun/CStrings.swift
    ${CMAKE_CURRENT_LIST_DIR}/Sources/Xtun/XtunError.swift
    ${CMAKE_CURRENT_LIST_DIR}/Sources/Xtun/XtunProxy.swift
    ${CMAKE_CURRENT_LIST_DIR}/Sources/Xtun/XtunTunnel.swift
)

if (XTUN_SWIFT_SLICE)
    if (CMAKE_SYSTEM_NAME STREQUAL "iOS")
        set(_os ios)
        set(_min_os ${XTUN_IOS_DEPLOYMENT_TARGET})
        set(_plist_platform iPhoneOS)
        if (CMAKE_OSX_SYSROOT MATCHES "[Ss]imulator")
            set(_env_suffix "-simulator")
            set(_plist_platform iPhoneSimulator)
        endif()
    elseif (CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        set(_os macos)
        set(_min_os ${XTUN_MACOS_DEPLOYMENT_TARGET})
        set(_plist_platform MacOSX)
    else()
        message(FATAL_ERROR "Xtun.framework: unsupported system '${CMAKE_SYSTEM_NAME}'")
    endif()

    if (CMAKE_OSX_ARCHITECTURES)
        set(_archs ${CMAKE_OSX_ARCHITECTURES})
    elseif(CMAKE_SYSTEM_NAME STREQUAL "iOS")
        set(_archs arm64)
    else()
        set(_archs ${CMAKE_SYSTEM_PROCESSOR})
    endif()

    set(_sdk ${CMAKE_OSX_SYSROOT})
    if (NOT IS_ABSOLUTE "${_sdk}")
        set(_xcrun_sdk)
        if (_sdk)
            set(_xcrun_sdk --sdk ${_sdk})
        endif()
        execute_process(
            COMMAND xcrun ${_xcrun_sdk} --show-sdk-path
            OUTPUT_VARIABLE _sdk
            OUTPUT_STRIP_TRAILING_WHITESPACE
            COMMAND_ERROR_IS_FATAL ANY)
    endif()

    execute_process(
        COMMAND xcrun --find swiftc
        OUTPUT_VARIABLE _swiftc
        OUTPUT_STRIP_TRAILING_WHITESPACE
        COMMAND_ERROR_IS_FATAL ANY)

    if (CMAKE_BUILD_TYPE STREQUAL "Debug")
        set(_swift_opt -Onone -g)
    else()
        set(_swift_opt -O)
    endif()

    # CXtun clang module, only visible while compiling the wrapper.
    set(_cxtun_dir ${CMAKE_CURRENT_BINARY_DIR}/cxtun)
    configure_file(${CMAKE_SOURCE_DIR}/include/xtun.h ${_cxtun_dir}/xtun.h COPYONLY)
    configure_file(${CMAKE_CURRENT_LIST_DIR}/module.modulemap ${_cxtun_dir}/module.modulemap COPYONLY)

    set(_stage ${CMAKE_CURRENT_BINARY_DIR}/stage)
    set(_swiftmodule ${_stage}/Xtun.swiftmodule)
    set(_swift_libs)
    foreach (_arch IN LISTS _archs)
        set(_module_triple ${_arch}-apple-${_os}${_env_suffix})
        set(_lib ${_stage}/${_arch}/libXtunSwift.a)

        add_custom_command(
            OUTPUT ${_lib}
                   ${_swiftmodule}/${_module_triple}.swiftmodule
                   ${_swiftmodule}/${_module_triple}.swiftinterface
            COMMAND ${CMAKE_COMMAND} -E make_directory ${_stage}/${_arch} ${_swiftmodule}
            COMMAND ${_swiftc}
                -target ${_arch}-apple-${_os}${_min_os}${_env_suffix}
                -sdk ${_sdk}
                -module-name Xtun
                -parse-as-library
                -swift-version 6
                ${_swift_opt}
                -whole-module-optimization
                -enable-library-evolution
                -emit-library -static
                -emit-module
                -emit-module-path ${_swiftmodule}/${_module_triple}.swiftmodule
                -emit-module-interface-path ${_swiftmodule}/${_module_triple}.swiftinterface
                -avoid-emit-module-source-info
                -module-cache-path ${CMAKE_CURRENT_BINARY_DIR}/module-cache
                -I ${_cxtun_dir}
                -o ${_lib}
                ${_swift_sources}
            DEPENDS ${_swift_sources} ${_cxtun_dir}/xtun.h ${_cxtun_dir}/module.modulemap
            COMMENT "Compiling Xtun Swift module (${_module_triple})"
            VERBATIM)
        list(APPEND _swift_libs ${_lib})
    endforeach()

    # macOS frameworks use the versioned bundle layout, iOS ones are flat.
    set(_fw ${CMAKE_CURRENT_BINARY_DIR}/Xtun.framework)
    if (_os STREQUAL "macos")
        set(_fw_root ${_fw}/Versions/A)
        set(_fw_plist ${_fw_root}/Resources/Info.plist)
        set(_fw_links
            COMMAND ${CMAKE_COMMAND} -E create_symlink A ${_fw}/Versions/Current
            COMMAND ${CMAKE_COMMAND} -E create_symlink Versions/Current/Xtun ${_fw}/Xtun
            COMMAND ${CMAKE_COMMAND} -E create_symlink Versions/Current/Modules ${_fw}/Modules
            COMMAND ${CMAKE_COMMAND} -E create_symlink Versions/Current/Resources ${_fw}/Resources)
    else()
        set(_fw_root ${_fw})
        set(_fw_plist ${_fw_root}/Info.plist)
        set(_fw_links)
    endif()

    set(XTUN_PLIST_PLATFORM ${_plist_platform})
    set(XTUN_PLIST_MIN_OS ${_min_os})
    configure_file(${CMAKE_CURRENT_LIST_DIR}/Info.plist.in ${CMAKE_CURRENT_BINARY_DIR}/Info.plist @ONLY)

    set_target_properties(${PROJECT_NAME} PROPERTIES
        ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib/$<CONFIG>)

    set(_fw_stamp ${CMAKE_CURRENT_BINARY_DIR}/Xtun.framework.stamp)
    add_custom_command(
        OUTPUT ${_fw_stamp}
        COMMAND ${CMAKE_COMMAND} -E rm -rf ${_fw}
        COMMAND ${CMAKE_COMMAND} -E make_directory ${_fw_root}/Modules
        COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_BINARY_DIR}/Info.plist ${_fw_plist}
        COMMAND libtool -static -no_warning_for_no_symbols -o ${_fw_root}/Xtun
            $<TARGET_FILE:${PROJECT_NAME}>
            $<TARGET_FILE:goxtun>
            ${_swift_libs}
        COMMAND ${CMAKE_COMMAND} -E copy_directory ${_swiftmodule} ${_fw_root}/Modules/Xtun.swiftmodule
        ${_fw_links}
        COMMAND ${CMAKE_COMMAND} -E touch ${_fw_stamp}
        DEPENDS ${PROJECT_NAME} goxtun ${_swift_libs} ${CMAKE_CURRENT_BINARY_DIR}/Info.plist
        COMMENT "Assembling Xtun.framework (${_os}${_env_suffix})"
        VERBATIM)
    add_custom_target(xtun_framework ALL DEPENDS ${_fw_stamp})

else()
    set(XTUN_APPLE_SLICES "macos;ios;ios-simulator" CACHE STRING
        "Slices bundled into Xtun.xcframework (macos, ios, ios-simulator)")
    set(XTUN_XCFRAMEWORK_URL "https://REPLACE_ME/Xtun.xcframework.zip" CACHE STRING
        "Download URL written into the generated SwiftPM manifest")

    include(ExternalProject)

    set(_slice_args_macos
        -DCMAKE_OSX_SYSROOT=macosx
        -DCMAKE_OSX_ARCHITECTURES=arm64|x86_64
        -DCMAKE_OSX_DEPLOYMENT_TARGET=${XTUN_MACOS_DEPLOYMENT_TARGET})
    set(_slice_args_ios
        -DCMAKE_SYSTEM_NAME=iOS
        -DCMAKE_OSX_SYSROOT=iphoneos
        -DCMAKE_OSX_ARCHITECTURES=arm64
        -DCMAKE_OSX_DEPLOYMENT_TARGET=${XTUN_IOS_DEPLOYMENT_TARGET})
    set(_slice_args_ios-simulator
        -DCMAKE_SYSTEM_NAME=iOS
        -DCMAKE_OSX_SYSROOT=iphonesimulator
        -DCMAKE_OSX_ARCHITECTURES=arm64|x86_64
        -DCMAKE_OSX_DEPLOYMENT_TARGET=${XTUN_IOS_DEPLOYMENT_TARGET})

    set(_slice_targets)
    set(_xcf_args)
    foreach (_slice IN LISTS XTUN_APPLE_SLICES)
        if (NOT DEFINED _slice_args_${_slice})
            message(FATAL_ERROR "XTUN_APPLE_SLICES: unknown slice '${_slice}'")
        endif()
        set(_bdir ${CMAKE_BINARY_DIR}/apple-${_slice})
        ExternalProject_Add(xtun-framework-${_slice}
            SOURCE_DIR ${CMAKE_SOURCE_DIR}
            BINARY_DIR ${_bdir}
            LIST_SEPARATOR |
            CMAKE_ARGS
                -DBINDINGS_SWIFT=ON
                -DXTUN_SWIFT_SLICE=ON
                -DBINDINGS_CPP=OFF
                -DBINDINGS_JAVA=OFF
                -DBUILD_TESTS=OFF
                -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
                -DXTUN_IOS_DEPLOYMENT_TARGET=${XTUN_IOS_DEPLOYMENT_TARGET}
                -DXTUN_MACOS_DEPLOYMENT_TARGET=${XTUN_MACOS_DEPLOYMENT_TARGET}
                ${_slice_args_${_slice}}
            BUILD_COMMAND ${CMAKE_COMMAND} --build <BINARY_DIR> --target xtun_framework
            INSTALL_COMMAND ""
            BUILD_ALWAYS ON
        )
        list(APPEND _slice_targets xtun-framework-${_slice})
        list(APPEND _xcf_args -framework ${_bdir}/swift/Xtun.framework)
    endforeach()

    set(_xcf ${CMAKE_BINARY_DIR}/Xtun.xcframework)
    set(_zip ${CMAKE_BINARY_DIR}/Xtun.xcframework.zip)
    set(_pkg_dir ${CMAKE_BINARY_DIR}/swiftpm)

    add_custom_target(xtun_xcframework ALL
        COMMAND ${CMAKE_COMMAND} -E rm -rf ${_xcf} ${_zip}
        COMMAND xcodebuild -create-xcframework ${_xcf_args} -output ${_xcf}
        COMMAND ditto -c -k --sequesterRsrc --keepParent ${_xcf} ${_zip}
        COMMAND ${CMAKE_COMMAND}
            -DZIP=${_zip}
            -DOUT_DIR=${_pkg_dir}
            -DTEMPLATE=${CMAKE_CURRENT_LIST_DIR}/Package.swift.in
            -DURL=${XTUN_XCFRAMEWORK_URL}
            -DIOS_VERSION=${XTUN_IOS_DEPLOYMENT_TARGET}
            -DMACOS_VERSION=${XTUN_MACOS_DEPLOYMENT_TARGET}
            -P ${CMAKE_CURRENT_LIST_DIR}/cmake/swiftpm_manifest.cmake
        COMMENT "Assembling Xtun.xcframework"
        VERBATIM)
    add_dependencies(xtun_xcframework ${_slice_targets})
endif()
