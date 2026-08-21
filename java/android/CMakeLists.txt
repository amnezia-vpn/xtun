include(ExternalProject)

set(AAR_STAGE ${CMAKE_BINARY_DIR}/aar)
file(MAKE_DIRECTORY ${AAR_STAGE})
get_target_property(_xtun_classes_jar xtun_classes JAR_FILE)

add_custom_target(xtun_aar_prebuild
    COMMAND ${CMAKE_COMMAND} -E rm -rf ${AAR_STAGE}
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_CURRENT_SOURCE_DIR}/AndroidManifest.xml"
        "${AAR_STAGE}/AndroidManifest.xml"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_CURRENT_SOURCE_DIR}/R.txt"
        "${AAR_STAGE}/R.txt"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${_xtun_classes_jar}"
        "${AAR_STAGE}/classes.jar"
    COMMENT "Staging Android files for .aar"
)
add_dependencies(xtun_aar_prebuild xtun_classes)

set(known_android_abis armeabi-v7a arm64-v8a x86 x86_64)
unset(xtun-jnis)

foreach(abi IN LISTS known_android_abis)
    if (NOT "${abi}" STREQUAL "${ANDROID_ABI}")
        ExternalProject_Add(xtun-jni-${abi}
            SOURCE_DIR ${CMAKE_SOURCE_DIR}
            BINARY_DIR ${CMAKE_BINARY_DIR}/android-${abi}
            CMAKE_ARGS
                -DBINDINGS_JAVA=ON
                -DCMAKE_TOOLCHAIN_FILE=${ANDROID_NDK}/build/cmake/android.toolchain.cmake
                -DANDROID_ABI=${abi}
                -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
            BUILD_COMMAND ${CMAKE_COMMAND} --build <BINARY_DIR> --target xtun-jni
            INSTALL_COMMAND ${CMAKE_COMMAND} --install <BINARY_DIR> --prefix ${AAR_STAGE} --component jni
            BUILD_ALWAYS ON
        )
    else()
        add_custom_target(xtun-jni-${abi}
            COMMAND "${CMAKE_COMMAND}" --install "${CMAKE_BINARY_DIR}" --prefix ${AAR_STAGE} --component jni
            DEPENDS xtun-jni
        )
    endif()
    add_dependencies(xtun-jni-${abi} xtun_aar_prebuild)
    list(APPEND xtun-jnis xtun-jni-${abi})
endforeach()

add_custom_target(xtun_aar ALL
    COMMAND ${CMAKE_COMMAND} -E tar cf ${CMAKE_BINARY_DIR}/xtun.aar --format=zip .
    WORKING_DIRECTORY ${AAR_STAGE}
    COMMENT "Assembling xtun.aar")
add_dependencies(xtun_aar xtun_aar_prebuild ${xtun-jnis})
