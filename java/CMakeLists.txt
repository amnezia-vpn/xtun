find_package(JNI REQUIRED)

add_library(xtun-jni SHARED
    ${CMAKE_CURRENT_LIST_DIR}/src/main/c/jni.c)
target_link_libraries(xtun-jni PRIVATE xtun JNI::JNI)

if (ANDROID)
    set(_xtun-jni-install-dir jni/${ANDROID_ABI})
else()
    set(_xtun-jni-install-dir jni)
endif()

install(TARGETS xtun-jni
    COMPONENT jni
    DESTINATION ${_xtun-jni-install-dir}
)
if (BUNDLE_GOXTUN)
    install(FILES "$<$<STREQUAL:$<TARGET_PROPERTY:goxtun,TYPE>,SHARED_LIBRARY>:$<TARGET_FILE:goxtun>>"
        COMPONENT jni
        DESTINATION ${_xtun-jni-install-dir}
    )
endif()

find_package(Java REQUIRED COMPONENTS Development)
include(UseJava)
add_jar(xtun_classes SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/src/main/java/org/amnezia/xtun/Xtun.java
    ${CMAKE_CURRENT_LIST_DIR}/src/main/java/org/amnezia/xtun/XtunException.java
    ${CMAKE_CURRENT_LIST_DIR}/src/main/java/org/amnezia/xtun/XtunProxy.java
    ${CMAKE_CURRENT_LIST_DIR}/src/main/java/org/amnezia/xtun/XtunTunnel.java
)

if (ANDROID)
    add_subdirectory(android)
endif()

if (BUILD_TESTS AND NOT CMAKE_CROSSCOMPILING)
    add_library(xtun-jni-test SHARED
        ${CMAKE_CURRENT_LIST_DIR}/src/test/c/jni.cpp)
    target_include_directories(xtun-jni-test PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/tests)
    target_link_libraries(xtun-jni-test PRIVATE xtun JNI::JNI)

    add_jar(xtun_test_classes
        SOURCES
            ${CMAKE_CURRENT_LIST_DIR}/src/test/java/org/amnezia/xtun/XtunTest.java
            ${CMAKE_CURRENT_LIST_DIR}/src/test/java/org/amnezia/xtun/XtunTestNative.java
        INCLUDE_JARS xtun_classes)
    add_dependencies(xtun_test_classes xtun-jni xtun-jni-test)

    get_target_property(_xtun_jar xtun_classes JAR_FILE)
    get_target_property(_xtun_test_jar xtun_test_classes JAR_FILE)
    if (WIN32)
        set(_cp "${_xtun_jar};${_xtun_test_jar}")
    else()
        set(_cp "${_xtun_jar}:${_xtun_test_jar}")
    endif()

    if (WIN32)
        set(_libpath "$<TARGET_FILE_DIR:xtun-jni>;$<TARGET_FILE_DIR:xtun-jni-test>")
    else()
        set(_libpath "$<TARGET_FILE_DIR:xtun-jni>:$<TARGET_FILE_DIR:xtun-jni-test>")
    endif()

    set(_xtun_jni_test_cases
        loadXtun
        attachFailsWhenTunFactoryFails
        attachFailsWhenTunFactoryThrows
        attachDetachWithTun
    )
    foreach(case IN LISTS _xtun_jni_test_cases)
        add_test(NAME jni.${case}
            COMMAND ${Java_JAVA_EXECUTABLE}
                -Xrs
                -ea
                -Djava.library.path=${_libpath}
                -cp "${_cp}"
                org.amnezia.xtun.XtunTest ${case})
        set_tests_properties(jni.${case} PROPERTIES
            SKIP_REGULAR_EXPRESSION "SKIP:"
            TIMEOUT 30)
    endforeach()
endif()
