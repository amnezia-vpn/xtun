file(SHA256 "${ZIP}" CHECKSUM)
configure_file("${TEMPLATE}" "${OUT_DIR}/Package.swift" @ONLY)
file(WRITE "${OUT_DIR}/Xtun.xcframework.zip.sha256" "${CHECKSUM}\n")
message(STATUS "Xtun.xcframework.zip checksum: ${CHECKSUM}")
