package org.amnezia.xtun;

final class XtunTestNative {
    static {
        System.loadLibrary("xtun-jni-test");
    }

    private XtunTestNative() {}

    static native boolean privileged();
    static native int createTun();
}
