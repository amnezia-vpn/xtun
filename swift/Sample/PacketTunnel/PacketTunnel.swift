import Darwin
import Foundation
import Network
import NetworkExtension
import os.log
import Xtun

final class PacketTunnelProvider: NEPacketTunnelProvider, @unchecked Sendable {
    private static let address4 = "10.111.0.2"
    private static let address6 = "fd00:111::2"
    private static let dnsA = "8.8.8.8"
    private static let dnsB = "8.8.4.4"
    
    private let log = Logger(subsystem: "org.amnezia.sample", category: "tunnel")
    private let queue = DispatchQueue(label: "org.amnezia.sample")
    
    private var proxy: XtunProxy?
    private var tunnel: XtunTunnel?
    private var monitor: NWPathMonitor?
    private var uplink: (interface: NWInterface?, gateways: [Network.NWEndpoint])?

    override func startTunnel(options: [String: NSObject]?,
                              completionHandler: @escaping (Error?) -> Void) {
        let providerConf = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration
        guard let conf = providerConf?["conf"] as? String, !conf.isEmpty else {
            completionHandler(Self.error("missing config"))
            return
        }
        let proto: XtunProxy.Proto
        switch providerConf?["proto"] as? String {
        case "awg": proto = .awg
        case "xray": proto = .xray
        case let other:
            completionHandler(Self.error("unknown proto \(other ?? "nil")"))
            return
        }
        
        queue.async {
            do {
                let proxy = try XtunProxy(proto: proto,
                                          config: conf,
                                          onSocket: nil,
                                          onLog: { self.log.notice("\($0, privacy: .public)") },
                                          onStatus: { self.log.notice("new status: \(String(describing: $0), privacy: .public)") })
                
                let tunnel = try XtunTunnel(ifAddrs: [Self.address4, Self.address6], dns: [Self.dnsA, Self.dnsB]) { dns, includeRoutes, excludeRoutes, mtu in
                    let (includeRoutes4, includeRoutes6) = try Self.parseRoutes(includeRoutes)
                    let (excludeRoutes4, excludeRoutes6) = try Self.parseRoutes(excludeRoutes)
                    
                    let v4settings = NEIPv4Settings(addresses: [Self.address4], subnetMasks: ["255.255.255.255"])
                    v4settings.includedRoutes = includeRoutes4
                    v4settings.excludedRoutes = excludeRoutes4
                    
                    let v6settings = NEIPv6Settings(addresses: [Self.address6], networkPrefixLengths: [128])
                    v6settings.includedRoutes = includeRoutes6
                    v6settings.excludedRoutes = excludeRoutes6
                    
                    let dnsSettings = NEDNSSettings(servers: dns)
                    
                    let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
                    settings.ipv4Settings = v4settings
                    settings.ipv6Settings = v6settings
                    settings.dnsSettings = dnsSettings
                    settings.mtu = NSNumber(value: mtu > 0 ? mtu : 1280)
                    
                    let done = DispatchSemaphore(value: 0)
                    var result: Error?
                    
                    self.setTunnelNetworkSettings(settings) { err in
                        result = err
                        done.signal()
                    }
                    done.wait()
                    
                    if let result { throw result }
                    
                    guard let fd = Self.utunFileDescriptor() else {
                        throw XtunError.deviceCreate
                    }
                    return fd
                }
                
                try tunnel.attach(proxy)
                
                self.proxy = proxy
                self.tunnel = tunnel

                let monitor = NWPathMonitor()
                monitor.pathUpdateHandler = { self.pathChanged($0) }
                monitor.start(queue: self.queue)
                self.monitor = monitor

                completionHandler(nil)
            } catch {
                completionHandler(Self.error(String(describing: error)))
            }
        }
    }
    
    override func stopTunnel(with reason: NEProviderStopReason,
                             completionHandler: @escaping () -> Void) {
        queue.async {
            self.monitor?.cancel()
            self.monitor = nil
            self.uplink = nil
            if let proxy = self.proxy, let tunnel = self.tunnel {
                tunnel.detach(proxy)
            }
            self.tunnel = nil
            self.proxy = nil
            completionHandler()
        }
    }
    
    private func pathChanged(_ path: Network.NWPath) {
        guard let tunnel, path.status == .satisfied else { return }
        let current = (interface: path.availableInterfaces.first, gateways: path.gateways)
        if let uplink, uplink != current {
            tunnel.networkChanged()
        }
        uplink = current
    }

    // MARK: - helpers

    private static func error(_ message: String) -> NSError {
        NSError(domain: "org.amnezia.sample", code: 1,
                userInfo: [NSLocalizedDescriptionKey: message])
    }
    
    private static func utunFileDescriptor() -> Int32? {
        let SYSPROTO_CONTROL: Int32 = 2
        let UTUN_OPT_IFNAME: Int32 = 2
        var name = [CChar](repeating: 0, count: Int(IFNAMSIZ))
        for fd: Int32 in 0...1024 {
            var len = socklen_t(name.count)
            if getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, &name, &len) == 0,
               String(cString: name).hasPrefix("utun") {
                return fd
            }
        }
        return nil
    }
    
    private static func parseRoutes(_ routes: [String]) throws -> ([NEIPv4Route], [NEIPv6Route]) {
        var routes4: [NEIPv4Route] = []
        var routes6: [NEIPv6Route] = []
        for prefix in routes {
            guard let (addr, len) = Self.splitPrefix(prefix) else {
                throw XtunError.invalidArgs
            }
            if addr.contains(":") {
                routes6.append(NEIPv6Route(destinationAddress: addr, networkPrefixLength: NSNumber(value: len)))
            } else {
                routes4.append(NEIPv4Route(destinationAddress: addr, subnetMask: Self.ipv4Mask(len)))
            }
        }
        return (routes4, routes6)
    }
    
    private static func splitPrefix(_ prefix: String) -> (String, Int)? {
        let parts = prefix.split(separator: "/", maxSplits: 1)
        guard parts.count == 2, let len = Int(parts[1]) else { return nil }
        return (String(parts[0]), len)
    }
    
    private static func ipv4Mask(_ len: Int) -> String {
        let mask: UInt32 = len <= 0 ? 0 : ~UInt32(0) << UInt32(32 - min(len, 32))
        return [24, 16, 8, 0].map { String((mask >> UInt32($0)) & 0xff) }.joined(separator: ".")
    }
}
