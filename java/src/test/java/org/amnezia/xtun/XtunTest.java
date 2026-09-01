package org.amnezia.xtun;

import java.lang.reflect.Method;

/*
 * Test driver for the JNI bindings. One process per test case so that a
 * hard crash in native code fails exactly one CTest test.
 *
 * Usage: java org.amnezia.xtun.XtunTest <case-name>
 */
public final class XtunTest {
    private static final String CONF_A =
        "[Interface]\n" +
        "PrivateKey = eILKb9wfYDEPs1F6ZLDY68NXGG/PhyBCHDBrEbjFHUo=\n" +
        "ListenPort = 56812\n" +
        "\n" +
        "[Peer]\n" +
        "PublicKey = +zSndNxFc8zH2X9gskHna9+6huH9WxbrIQ0NOKdkUGg=\n" +
        "Endpoint = 127.0.0.1:56811\n";

    private static final String CONF_B =
        "[Interface]\n" +
        "PrivateKey = 4JSBkhMsSD7yflKRkU9aN6leuoFOhtHbHa0WZnmAcWU=\n" +
        "ListenPort = 56811\n" +
        "\n" +
        "[Peer]\n" +
        "PublicKey = /BC4JbwlpUOAEPmnJ+848kqgqJQbQZV+bSNzh2Hm2hg=\n" +
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

    public static void awgConfig() {
        try (XtunProxy proxy = new XtunProxy(XtunProxy.Proto.AWG, CONF_A,
            sock -> { System.out.println("[AWG]: new socket(" + sock + ") created"); },
            log -> { System.out.println("[AWG]: " + log); },
            status -> { System.out.println("[AWG]: status " + status); }
        )) {};
    }
}
