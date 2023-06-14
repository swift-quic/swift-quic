//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftQUIC open source project
//
// Copyright (c) 2023 the SwiftQUIC project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftQUIC project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

struct Version: RawRepresentable {
    typealias RawValue = UInt32

    private let data: RawValue
    var rawValue: RawValue { self.data }
    init(rawValue: RawValue) {
        self.data = rawValue
    }
}

extension Version {
    /// https://datatracker.ietf.org/doc/draft-ietf-quic-v2/
    static let version2: Version = 2
    /// https://datatracker.ietf.org/doc/html/rfc9001
    static let version1: Version = 1
    /// https://datatracker.ietf.org/doc/html/draft-ietf-quic-tls-29
    static let versionDraft29: Version = 0xff00_001d
}

extension Version {
    static let negotiation: Version = 0
}

extension Version: ExpressibleByIntegerLiteral {
    init(integerLiteral value: RawValue) {
        self.init(rawValue: value)
    }
}

extension Version: QuicType {
    init(with bytes: UnsafeBufferPointer<UInt8>) {
        let rawPointer = UnsafeRawBufferPointer(bytes)
        self.init(rawValue: RawValue(bigEndian: rawPointer.load(as: RawValue.self)))
    }

    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try Swift.withUnsafeBytes(of: self.rawValue.bigEndian, body)
    }
}

extension Version: Codable {}

private extension Version {
    func isNegotiation() -> Bool {
        self.data == 0
    }

    func isReserved() -> Bool {
        self.data & 0x0f0f0f0f == 0x0a0a0a0a
    }
}

func isNegotiation(version: Version) -> Bool {
    version.isNegotiation()
}

func isReserved(version: Version) -> Bool {
    version.isReserved()
}

extension Version: CustomStringConvertible {
    var description: String {
        switch self {
            case .version2: return "Version 2"
            case .version1: return "Version 1"
            case .versionDraft29: return "Draft 29"
            case .negotiation: return "Negotation"
            default:
                return "Unknown Version `\(self.data)`"
        }
    }
}

extension Version {
    var bytes: [UInt8] {
        Swift.withUnsafeBytes(of: self.rawValue.bigEndian, Array.init)
    }
}
