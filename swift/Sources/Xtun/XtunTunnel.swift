internal import CXtun
import Foundation

public final class XtunTunnel: @unchecked Sendable {
    public typealias TunFactory =
        @Sendable (_ dns: [String], _ includeRoutes: [String], _ excludeRoutes: [String], _ mtu: Int32) throws -> Int32

    private let raw: UnsafeMutablePointer<libxtun_tunnel>
    private let factory: TunFactory

    public init(ifAddrs: [String], factory: @escaping TunFactory) throws {
        self.factory = factory
        raw = .allocate(capacity: 1)
        raw.initialize(to: libxtun_tunnel())

        let priv = Unmanaged.passUnretained(self).toOpaque()

        try withCStringArray(ifAddrs) { ptrs in
            var tf = libxtun_tunfactory()
            tf.size = MemoryLayout<libxtun_tunfactory>.size
            tf.factory_priv = priv
            tf.factory_func = { dns, includeRoutes, excludeRoutes, mtu, priv in 
                return Unmanaged<XtunTunnel>.fromOpaque(priv!)._withUnsafeGuaranteedRef {
                    (try? $0.factory(stringArray(dns), stringArray(includeRoutes), stringArray(excludeRoutes), mtu)) ?? -1
                }
            }
            tf.if_addrs = ptrs
            try XtunError.check(libxtun_tunnel_new_from_tunfactory(raw, &tf))
        }
    }

    public func start() throws {
        try XtunError.check(libxtun_tunnel_start(raw))
    }

    public func attach(_ proxy: XtunProxy) throws {
        try XtunError.check(libxtun_tunnel_attach_proxy(raw, proxy.raw))
    }

    public func detach(_ proxy: XtunProxy) {
        libxtun_tunnel_detach_proxy(raw, proxy.raw)
    }

    public func networkChanged() {
        libxtun_tunnel_network_changed(raw)
    }

    deinit {
        libxtun_tunnel_free(raw)
        raw.deinitialize(count: 1)
        raw.deallocate()
    }
}
