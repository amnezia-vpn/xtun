package org.amnezia.xtun;

public final class XtunTunnel implements AutoCloseable {
    private long handle;

    public XtunTunnel(int fd) {
        Xtun.load();
        handle = nativeInit(fd);
    }

    @Override
    public void close() {
        nativeFree(handle);
        handle = 0;
    }

    public void attachProxy(XtunProxy proxy) {
        nativeAttachProxy(handle, proxy);
    }

    private static native long nativeInit(int fd);
    private static native void nativeFree(long handle);
    private static native void nativeAttachProxy(long handle, XtunProxy proxy);
}
