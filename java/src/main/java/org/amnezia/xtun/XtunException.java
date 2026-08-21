package org.amnezia.xtun;

public class XtunException extends RuntimeException {
    public static final int LIBXTUN_OK = 0;
    public static final int LIBXTUN_ERR_INVALID_ARGS = -1;
    public static final int LIBXTUN_ERR_DRIVER_UNAVAILABLE = -2;
    public static final int LIBXTUN_ERR_DEVICE_CREATE = -3;
    public static final int LIBXTUN_ERR_SYSTEM = -4;

    public static final int LIBXTUN_ERR_JNI_NOMEM = -10000;
    public static final int LIBXTUN_ERR_JNI_WRONG_PROTO = -10001;
    public static final int LIBXTUN_ERR_JNI_CLOSED = -10002;

    private final int code;

    public XtunException(int code) {
        super(describe(code));
        this.code = code;
    }

    public int code() {
        return code;
    }

    private static String describe(int code) {
        switch (code) {
            case LIBXTUN_OK:
                return "ok";
            case LIBXTUN_ERR_INVALID_ARGS:
                return "invalid args";
            case LIBXTUN_ERR_DRIVER_UNAVAILABLE:
                return "driver unavailable";
            case LIBXTUN_ERR_DEVICE_CREATE:
                return "failed to create device";
            case LIBXTUN_ERR_SYSTEM:
                return "system error";
            case LIBXTUN_ERR_JNI_NOMEM:
                return "JNI: out of memory";
            case LIBXTUN_ERR_JNI_WRONG_PROTO:
                return "JNI: wrong protocol";
            case LIBXTUN_ERR_JNI_CLOSED:
                return "JNI: the instance is closed";
            default:
                return "unknown error: " + code;
        }
    }
}
