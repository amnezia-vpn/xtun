func withCStringArray<R>(
    _ strings: [String],
    _ body: (UnsafePointer<UnsafePointer<CChar>?>) throws -> R
) throws -> R {
    var ptrs: [UnsafePointer<CChar>?] = []
    ptrs.reserveCapacity(strings.count + 1)

    func getPtr(_ i: Int) throws -> R {
        if i == strings.endIndex {
            ptrs.append(nil)
            return try body(ptrs)
        }
        return try strings[i].withCString({
            ptrs.append($0)
            return try getPtr(i + 1)
        })
    }
    return try getPtr(0)
}

func stringArray(_ list: UnsafePointer<UnsafePointer<CChar>?>?) -> [String] {
    guard var p = list else { return [] }
    var out: [String] = []
    while let s = p.pointee {
        out.append(String(cString: s))
        p += 1
    }
    return out
}
