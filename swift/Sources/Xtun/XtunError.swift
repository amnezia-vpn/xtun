internal import CXtun

public enum XtunError: Error, Hashable, Sendable, CustomStringConvertible {
    case invalidArgs
    case unsupported
    case driverUnavailable
    case deviceCreate
    case killswitch
    case system
    case unknown(Int32)

    init(code: Int32) {
        switch libxtun_error(rawValue: code) {
        case LIBXTUN_ERR_INVALID_ARGS: self = .invalidArgs
        case LIBXTUN_ERR_UNSUPPORTED: self = .unsupported
        case LIBXTUN_ERR_DRIVER_UNAVAILABLE: self = .driverUnavailable
        case LIBXTUN_ERR_DEVICE_CREATE: self = .deviceCreate
        case LIBXTUN_ERR_KILLSWITCH: self = .killswitch
        case LIBXTUN_ERR_SYSTEM: self = .system
        default: self = .unknown(code)
        }
    }

    public var code: Int32 {
        switch self {
        case .invalidArgs: return LIBXTUN_ERR_INVALID_ARGS.rawValue
        case .unsupported: return LIBXTUN_ERR_UNSUPPORTED.rawValue
        case .driverUnavailable: return LIBXTUN_ERR_DRIVER_UNAVAILABLE.rawValue
        case .deviceCreate: return LIBXTUN_ERR_DEVICE_CREATE.rawValue
        case .killswitch: return LIBXTUN_ERR_KILLSWITCH.rawValue
        case .system: return LIBXTUN_ERR_SYSTEM.rawValue
        case .unknown(let code): return code
        }
    }

    public var description: String {
        return String(cString: libxtun_strerror(code))
    }

    static func check(_ rc: Int32) throws {
        if rc != LIBXTUN_OK.rawValue {
            throw XtunError(code: rc)
        }
    }
}
