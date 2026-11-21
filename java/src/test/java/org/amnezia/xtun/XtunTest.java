package org.amnezia.xtun;

import java.lang.reflect.Method;

public final class XtunTest {
    private static final String CONF_A =
        "[Interface]\n" +
        "PrivateKey = eILKb9wfYDEPs1F6ZLDY68NXGG/PhyBCHDBrEbjFHUo=\n" +
        "ListenPort = 56812\n" +
        "\n" +
        "[Peer]\n" +
        "PublicKey = +zSndNxFc8zH2X9gskHna9+6huH9WxbrIQ0NOKdkUGg=\n" +
        "Endpoint = 127.0.0.1:56811\n";
    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.err.println("usage: XtunTest <case-name>");
            System.exit(2);
        }
        Method m = XtunTest.class.getDeclaredMethod(args[0]);
        m.setAccessible(true);
        m.invoke(null);
        System.out.println("PASS " + args[0]);
    }

    public static void loadXtun() {
        Xtun.load();
    }

    public static void attachFailsWhenTunFactoryFails() {
        try (XtunProxy proxy = newAwgProxy(CONF_A);
            XtunTunnel tunnel = new XtunTunnel((dns, includeRoutes, excludeRoutes, mtu) -> {
                check(dns != null && includeRoutes != null && excludeRoutes != null, "JNI passed null dns/includeRoutes/excludeRoutes");
                return -1;
            }, new String[]{"10.0.0.1"}, new String[]{"8.8.8.8"})) {
            expectError(XtunException.LIBXTUN_ERR_DEVICE_CREATE, () -> tunnel.attachProxy(proxy));
            tunnel.detachProxy(proxy);
        }
    }

    public static void attachFailsWhenTunFactoryThrows() {
        try (XtunProxy proxy = newAwgProxy(CONF_A);
            XtunTunnel tunnel = new XtunTunnel((dns, includeRoutes, excludeRoutes, mtu) -> {
                throw new IllegalStateException("factory failure");
            }, new String[]{"10.0.0.1"}, new String[]{"8.8.8.8"})) {
            expectError(XtunException.LIBXTUN_ERR_DEVICE_CREATE, () -> tunnel.attachProxy(proxy));
            tunnel.detachProxy(proxy);
        }
    }

    public static void attachDetachWithTun() {
        skipUnless(XtunTestNative.privileged(), "creating a tun device requires root");

        try (XtunProxy proxy = newAwgProxy(CONF_A);
            XtunTunnel tunnel = new XtunTunnel((dns, includeRoutes, excludeRoutes, mtu) -> {
                return XtunTestNative.createTun();
            }, new String[]{"10.0.0.1"}, new String[]{"8.8.8.8"})) {
            tunnel.attachProxy(proxy);
            tunnel.detachProxy(proxy);
        }
    }

    private static XtunProxy newAwgProxy(String conf) {
        return new XtunProxy.Builder()
            .withSocketHandler(sock -> System.out.println("[Proxy]: new socket(" + sock + ") created"))
            .withLogHandler(log -> System.out.println("[Proxy]: " + log))
            .withStatusHandler(status -> System.out.println("[Proxy]: status " + status))
            .build(XtunProxy.Proto.AWG, conf);
    }

    private static void check(boolean cond, String msg) {
        if (!cond)
            throw new AssertionError(msg);
    }

    private static void expectError(int code, Runnable action) {
        try {
            action.run();
        } catch (XtunException ex) {
            check(ex.code() == code, "expected error " + code + ", got " + ex.code() + " (" + ex.getMessage() + ")");
            return;
        }
        throw new AssertionError("expected XtunException(" + code + "), nothing was thrown");
    }

    private static void skipUnless(boolean cond, String reason) {
        if (!cond) {
            System.out.println("SKIP: " + reason);
            System.exit(0);
        }
    }
}
