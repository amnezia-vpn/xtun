internal import CXtun

public final class XtunProxy: @unchecked Sendable {
    public enum Proto: Sendable {
        case awg
        case xray

        var cValue: libxtun_proxy_proto {
            switch self {
            case .awg: return LIBXTUN_PROXY_PROTO_AWG
            case .xray: return LIBXTUN_PROXY_PROTO_XRAY
            }
        }
    }

    public enum Status: Sendable, Equatable {
        case disconnected
        case connected
        case noNetwork
        case unknown(Int32)

        init(_ raw: Int32) {
            switch raw {
            case Int32(LIBXTUN_STATUS_DISCONNECTED.rawValue): self = .disconnected
            case Int32(LIBXTUN_STATUS_CONNECTED.rawValue): self = .connected
            case Int32(LIBXTUN_STATUS_NO_NETWORK.rawValue): self = .noNetwork
            default: self = .unknown(raw)
            }
        }
    }

    public typealias SocketHandler = @Sendable (_ fd: Int32) -> Void
    public typealias LogHandler = @Sendable (_ line: String) -> Void
    public typealias StatusHandler = @Sendable (_ status: Status) -> Void

    let raw: UnsafeMutablePointer<libxtun_proxy>
    private let onSocket: SocketHandler?
    private let onLog: LogHandler?
    private let onStatus: StatusHandler?

    public init(
        proto: Proto,
        config: String,
        includeRoutes: [String] = [],
        excludeRoutes: [String] = [],
        onSocket: SocketHandler? = nil,
        onLog: LogHandler? = nil,
        onStatus: StatusHandler? = nil
    ) throws {
        self.onSocket = onSocket
        self.onLog = onLog
        self.onStatus = onStatus
        raw = .allocate(capacity: 1)
        raw.initialize(to: libxtun_proxy())

        let priv = Unmanaged.passUnretained(self).toOpaque()

        raw.pointee.onsockspawn = { fd, priv in
            Unmanaged<XtunProxy>.fromOpaque(priv!)._withUnsafeGuaranteedRef { $0.onSocket?(fd) }
        }
        raw.pointee.onsockspawn_priv = priv
        raw.pointee.loghandler = { str, priv in
            guard let str else { return }
            Unmanaged<XtunProxy>.fromOpaque(priv!)._withUnsafeGuaranteedRef {
                $0.onLog?(String(cString: str))
            }
        }
        raw.pointee.loghandler_priv = priv
        raw.pointee.statushandler = { status, priv in
            Unmanaged<XtunProxy>.fromOpaque(priv!)._withUnsafeGuaranteedRef {
                $0.onStatus?(Status(status))
            }
        }
        raw.pointee.statushandler_priv = priv

        let rc = try withCStringArray(includeRoutes) { includePtrs in
            try withCStringArray(excludeRoutes) { excludePtrs in
                var opts = libxtun_proxy_opts()
                opts.size = MemoryLayout<libxtun_proxy_opts>.size
                opts.includeRoutes = includePtrs
                opts.excludeRoutes = excludePtrs
                return config.withCString { libxtun_proxy_new(raw, proto.cValue, $0, &opts) }
            }
        }
        if rc != LIBXTUN_OK.rawValue {
            throw XtunError(code: rc)
        }
    }

    deinit {
        libxtun_proxy_free(raw)
        raw.deinitialize(count: 1)
        raw.deallocate()
    }
}
