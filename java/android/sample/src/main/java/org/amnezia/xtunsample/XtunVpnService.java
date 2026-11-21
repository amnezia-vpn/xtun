package org.amnezia.xtunsample;

import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.IpPrefix;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.net.VpnService;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;

import org.amnezia.xtun.XtunException;
import org.amnezia.xtun.XtunProxy;
import org.amnezia.xtun.XtunTunnel;

public class XtunVpnService extends VpnService {
    static final String ACTION_START = "org.amnezia.xtun.example.START";
    static final String ACTION_STOP = "org.amnezia.xtun.example.STOP";

    private static final String ADDRESS4 = "10.111.0.2";
    private static final String ADDRESS6 = "fd00:111::2";
    private static final String DNS_A = "8.8.8.8";
    private static final String DNS_B = "8.8.4.4";

    private XtunProxy proxy;
    private XtunTunnel tunnel;

    private static final NetworkRequest UPLINK = new NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build();

    private final Handler main = new Handler(Looper.getMainLooper());
    private List<LinkAddress> uplink;

    private final ConnectivityManager.NetworkCallback callback = new ConnectivityManager.NetworkCallback() {
        @Override
        public void onLinkPropertiesChanged(Network network, LinkProperties linkProperties) {
            List<LinkAddress> addrs = linkProperties.getLinkAddresses();
            main.post(() -> {
                if (tunnel == null) {
                    return;
                }
                if (uplink != null && !uplink.equals(addrs)) {
                    tunnel.networkChanged();
                }
                uplink = addrs;
            });
        }
    };

    private void connect(XtunProxy.Proto proto, String conf) {
        disconnect();
        try {
            proxy = new XtunProxy.Builder()
                    .withSocketHandler(this::protect)
                    .withLogHandler(log -> Log.d("awg", log))
                    .withStatusHandler(status -> Log.d("status", "status " + status))
                    .build(proto, conf);
            tunnel = new XtunTunnel((dns, includeRoutes, excludeRoutes, mtu) -> {
                Builder builder = new Builder()
                        .setSession("xtun")
                        .setMtu(mtu > 0 ? mtu : 1280)
                        .addAddress(ADDRESS4, 32)
                        .addAddress(ADDRESS6, 128);

                for (String addr : dns) {
                    builder.addDnsServer(addr);
                }
                for (String prefix : includeRoutes) {
                    int slash = prefix.indexOf('/');
                    try {
                        builder.addRoute(prefix.substring(0, slash), Integer.parseInt(prefix.substring(slash + 1)));
                    } catch (IllegalArgumentException | IndexOutOfBoundsException e) {
                        Log.w("xtun", "skipping route " + prefix, e);
                    }
                }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    for (String prefix : excludeRoutes) {
                        int slash = prefix.indexOf('/');
                        try {
                            builder.excludeRoute(new IpPrefix(InetAddress.getByName(prefix.substring(0, slash)),
                                    Integer.parseInt(prefix.substring(slash + 1))));
                        } catch (UnknownHostException | IllegalArgumentException | IndexOutOfBoundsException e) {
                            Log.w("xtun", "skipping excluded route " + prefix, e);
                        }
                    }
                } else if (excludeRoutes.length > 0) {
                    Log.w("xtun", "excluded routes need API " + Build.VERSION_CODES.TIRAMISU);
                }

                ParcelFileDescriptor fd = builder.establish();
                if (fd == null) {
                    Log.e("xtun", "establish() failed");
                    return -1;
                }
                return fd.detachFd();
            }, new String[]{ADDRESS4, ADDRESS6}, new String[]{ DNS_A, DNS_B });
            getSystemService(ConnectivityManager.class).requestNetwork(UPLINK, callback);
            tunnel.attachProxy(proxy);
        } catch (XtunException ex) {
            Log.d("xtun", ex.toString());
        }
    }

    private void disconnect() {
        if (tunnel != null) {
            getSystemService(ConnectivityManager.class).unregisterNetworkCallback(callback);
            uplink = null;
            tunnel.close();
            tunnel = null;
        }
        if (proxy != null) {
            proxy.close();
            proxy = null;
        }
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent != null ? intent.getAction() : null;
        if (ACTION_START.equals(action)) {
            String conf = intent.getStringExtra("conf");
            XtunProxy.Proto proto = XtunProxy.Proto.values()[intent.getIntExtra("proto", 0)];
            connect(proto, conf);
        } else if (ACTION_STOP.equals(action)) {
            disconnect();
        }
        return START_NOT_STICKY;
    }

    @Override
    public void onDestroy() {
        disconnect();
    }

    @Override
    public void onRevoke() {
        disconnect();
    }
}
