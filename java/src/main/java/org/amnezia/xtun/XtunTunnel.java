package org.amnezia.xtun;

public final class XtunTunnel implements AutoCloseable {

    public interface TunFactory {
        int createTun(String[] dns, String[] includeRoutes, String[] excludeRoutes, int mtu);
    }

    private long handle;

    public XtunTunnel(TunFactory factory, String[] ifaddrs) {
        Xtun.load();
        handle = nativeInit(factory, ifaddrs);
    }

    @Override
    public void close() {
        nativeFree(handle);
        handle = 0;
    }

    public void start() {
        nativeStart(handle);
    }

    public void attachProxy(XtunProxy proxy) {
        nativeAttachProxy(handle, proxy);
    }

    public void detachProxy(XtunProxy proxy) {
        nativeDetachProxy(handle, proxy);
    }

    public void networkChanged() {
        nativeNetworkChanged(handle);
    }

    private static native long nativeInit(TunFactory factory, String[] ifaddrs);
    private static native void nativeFree(long handle);
    private static native void nativeStart(long handle);
    private static native void nativeAttachProxy(long handle, XtunProxy proxy);
    private static native void nativeDetachProxy(long handle, XtunProxy proxy);
    private static native void nativeNetworkChanged(long handle);
}
