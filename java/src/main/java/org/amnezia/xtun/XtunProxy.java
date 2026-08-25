package org.amnezia.xtun;

public final class XtunProxy implements AutoCloseable {
    public enum Proto {
        AWG(1),
        VLESS(2);

        private final int value;

        Proto(int value) {
            this.value = value;
        }

        public int getValue() {
            return value;
        }
    }

    public interface SocketHandler {
        void onSocketCreated(int socket);
    }

    public interface LogHandler {
        void onLog(String log);
    }

    public interface StatusHandler {
        void onStatus(int status);
    }

    private long handle;

    public XtunProxy(Proto proto, String conf, SocketHandler socketHandler, LogHandler logHandler,
                     StatusHandler statusHandler) {
        Xtun.load();
        handle = nativeInit(proto.getValue(), conf, socketHandler, logHandler, statusHandler);
    }

    @Override
    public void close() {
        nativeFree(handle);
        handle = 0;
    }

    private static native long nativeInit(int proto, String conf, SocketHandler socketHandler, LogHandler logHandler, StatusHandler statusHandler);
    private static native void nativeFree(long handle);
}
