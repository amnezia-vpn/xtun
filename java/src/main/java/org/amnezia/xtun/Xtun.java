package org.amnezia.xtun;

public final class Xtun {
    private static boolean loaded = false;

    private Xtun() {}

    public static synchronized void load() {
        if (!loaded) {
            System.loadLibrary("xtun-jni");
            loaded = true;
        }
    }
}
