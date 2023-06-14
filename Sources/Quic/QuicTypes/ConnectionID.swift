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

struct ConnectionID: RawRepresentable {
    typealias RawValue = [UInt8]

    private let data: RawValue
    var rawValue: RawValue { self.data }
    init(rawValue: RawValue) {
        self.data = rawValue
    }

    var length: Int { self.data.count }

    /// Returns the ConnectionID's raw value prefixed with it's byte length as a UVarInt
    var lengthPrefixedBytes: [UInt8] {
        if self.length == 0 { return [0x00] }
        return writeQuicVarInt(UInt64(self.length)) + self.data
    }
}

extension ConnectionID: ExpressibleByArrayLiteral {
    init(arrayLiteral elements: RawValue.Element...) {
        self.init(rawValue: elements)
    }

    init(randomOfLength length: Int) {
        self.data = (0..<length).map { _ in UInt8.random(in: UInt8.min...UInt8.max) }
    }
}

extension ConnectionID: QuicType {
    init<S>(with bytes: S) where S: Sequence, S.Element == UInt8 {
        self.init(rawValue: RawValue(bytes))
    }

    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try self.rawValue.withUnsafeBytes(body)
    }
}

extension ConnectionID: Codable {}
