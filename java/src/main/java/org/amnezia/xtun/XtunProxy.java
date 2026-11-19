package org.amnezia.xtun;

public final class XtunProxy implements AutoCloseable {
    public enum Proto {
        AWG(1),
        XRAY(2);

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

    public static final class Builder {
        private String[] includeRoutes;
        private String[] excludeRoutes;
        private SocketHandler socketHandler = socket -> {};
        private LogHandler logHandler = log -> {};
        private StatusHandler statusHandler = status -> {};

        public Builder withIncludeRoutes(String[] includeRoutes) {
            this.includeRoutes = includeRoutes;
            return this;
        }

        public Builder withExcludeRoutes(String[] excludeRoutes) {
            this.excludeRoutes = excludeRoutes;
            return this;
        }

        public Builder withSocketHandler(SocketHandler socketHandler) {
            this.socketHandler = socketHandler;
            return this;
        }

        public Builder withLogHandler(LogHandler logHandler) {
            this.logHandler = logHandler;
            return this;
        }

        public Builder withStatusHandler(StatusHandler statusHandler) {
            this.statusHandler = statusHandler;
            return this;
        }

        public XtunProxy build(Proto proto, String conf) {
            return new XtunProxy(proto, conf, includeRoutes, excludeRoutes, socketHandler, logHandler, statusHandler);
        }
    }

    private long handle;

    private XtunProxy(Proto proto, String conf, String[] includeRoutes, String[] excludeRoutes, SocketHandler socketHandler,
                      LogHandler logHandler, StatusHandler statusHandler) {
        Xtun.load();
        handle = nativeInit(proto.getValue(), conf, includeRoutes, excludeRoutes, socketHandler, logHandler, statusHandler);
    }

    @Override
    public void close() {
        nativeFree(handle);
        handle = 0;
    }

    private static native long nativeInit(int proto, String conf, String[] includeRoutes, String[] excludeRoutes, SocketHandler socketHandler, LogHandler logHandler, StatusHandler statusHandler);
    private static native void nativeFree(long handle);
}
