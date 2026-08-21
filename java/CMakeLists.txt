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
    install(FILES "$<$<STREQUAL:$<TARGET_PROPERTY:amnezia::goxtun,TYPE>,SHARED_LIBRARY>:$<TARGET_FILE:amnezia::goxtun>>"
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
    add_jar(xtun_test_classes
        SOURCES ${CMAKE_CURRENT_LIST_DIR}/src/test/java/org/amnezia/xtun/XtunTest.java
        INCLUDE_JARS xtun_classes)
    add_dependencies(xtun_test_classes xtun-jni)

    get_target_property(_xtun_jar xtun_classes JAR_FILE)
    get_target_property(_xtun_test_jar xtun_test_classes JAR_FILE)
    if (WIN32)
        set(_cp "${_xtun_jar};${_xtun_test_jar}")
    else()
        set(_cp "${_xtun_jar}:${_xtun_test_jar}")
    endif()

    set(_xtun_jni_test_cases
        loadXtun
        awgConfig
    )
    foreach(case IN LISTS _xtun_jni_test_cases)
        add_test(NAME jni.${case}
            COMMAND ${Java_JAVA_EXECUTABLE}
                -Xcheck:jni
                -Xrs
                -ea
                -Djava.library.path=$<TARGET_FILE_DIR:xtun-jni>
                -cp "${_cp}"
                org.amnezia.xtun.XtunTest ${case})
    endforeach()
endif()
