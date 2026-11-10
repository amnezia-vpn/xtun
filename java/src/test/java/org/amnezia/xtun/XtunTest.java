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
            XtunTunnel tunnel = new XtunTunnel((dns, routes, mtu) -> {
                check(dns != null && routes != null, "JNI passed null dns/routes");
                return -1;
            }, new String[]{"10.0.0.1"})) {
            expectError(XtunException.LIBXTUN_ERR_DEVICE_CREATE, () -> tunnel.attachProxy(proxy));
            tunnel.detachProxy(proxy);
        }
    }

    public static void attachFailsWhenTunFactoryThrows() {
        try (XtunProxy proxy = newAwgProxy(CONF_A);
            XtunTunnel tunnel = new XtunTunnel((dns, routes, mtu) -> {
                throw new IllegalStateException("factory failure");
            }, new String[]{"10.0.0.1"})) {
            expectError(XtunException.LIBXTUN_ERR_DEVICE_CREATE, () -> tunnel.attachProxy(proxy));
            tunnel.detachProxy(proxy);
        }
    }

    public static void attachDetachWithTun() {
        skipUnless(XtunTestNative.privileged(), "creating a tun device requires root");

        try (XtunProxy proxy = newAwgProxy(CONF_A);
            XtunTunnel tunnel = new XtunTunnel((dns, routes, mtu) -> {
                return XtunTestNative.createTun();
            }, new String[]{"10.0.0.1"})) {
            tunnel.attachProxy(proxy);
            tunnel.detachProxy(proxy);
        }
    }

    private static XtunProxy newAwgProxy(String conf) {
        return new XtunProxy(XtunProxy.Proto.AWG, conf, null, null,
            sock -> System.out.println("[Proxy]: new socket(" + sock + ") created"),
            log -> System.out.println("[Proxy]: " + log),
            status -> System.out.println("[Proxy]: status " + status));
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
