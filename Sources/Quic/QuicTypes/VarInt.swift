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

struct VarInt: RawRepresentable {
    typealias RawValue = UInt64

    private let buffer: [UInt8]
    private let data: RawValue
    public var rawValue: RawValue { self.data }
    init?(rawValue: RawValue) {
        guard rawValue < VarInt.upperBound else {
            return nil
        }

        switch rawValue {
            case ..<0x40:
                let value = UInt8(exactly: rawValue)!
                self.buffer = bytes(of: value)
            case 0x40..<0x4000:
                let value = UInt16(exactly: rawValue)! | 0x4000
                self.buffer = bytes(of: value)
            case 0x4000..<0x4000_0000:
                let value = UInt32(exactly: rawValue)! | 0x8000_0000
                self.buffer = bytes(of: value)
            default:
                precondition(rawValue < VarInt.upperBound)
                let value = rawValue | 0xc000_0000_0000_0000
                self.buffer = bytes(of: value)
        }

        self.data = rawValue
    }

    static let upperBound: RawValue = 1 << 62
    static var maxRawValue: RawValue { upperBound - 1 }
    static var max: VarInt { VarInt(rawValue: maxRawValue)! }
}

extension VarInt: ExpressibleByIntegerLiteral {
    init(integerLiteral value: RawValue) {
        precondition(value < VarInt.upperBound)
        self.init(rawValue: value)!
    }
}

extension VarInt: QuicType {
    init<S: Sequence>(with bytes: S) where S.Element == UInt8 {
        guard let firstByte = bytes.first(where: { _ in true }) else {
            self = 0
            return
        }

        let prefix = firstByte >> 6
        let length = 1 << prefix

        let remaining = bytes.dropFirst().prefix(length - 1)
        let value = remaining.reduce(UInt64(firstByte & 0x3f)) {
            $0 << 8 + UInt64($1)
        }

        self.init(integerLiteral: value)
    }

    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try self.buffer.withUnsafeBytes(body)
    }
}

func bytes<T>(of value: T) -> [UInt8] where T: FixedWidthInteger {
    withUnsafeBytes(of: value.bigEndian) { $0.map { $0 } }
}

func writeQuicVarInt(_ num: UInt64, minBytes: Int = 0) -> [UInt8] {
    func getLength(_ bytes: Int) -> UInt8 {
        switch bytes {
            case 1: return 0
            case 2: return 1
            case 3, 4: return 2
            case 5...8: return 3
            default: return 0
        }
    }

    var bytes: [UInt8] = num.bytes(minBytes: minBytes)
    guard !bytes.isEmpty else { return [0] }

    let length = getLength(bytes.count)
    if (bytes[0] >> 6) == 0 && (minBytes <= bytes.count) {
        // encode the length in the two available bits
        bytes[0] ^= (UInt8(length) << 6)
    } else {
        // add a new byte to store the length
        bytes.insert(UInt8(length + 1) << 6, at: 0)
    }
    return bytes
}

extension Array where Element == UInt8 {
    // https://www.rfc-editor.org/rfc/rfc9000.html#name-sample-variable-length-inte
    func readQuicVarInt() -> UInt64? {
        guard let firstByte = self.first else {
            return nil
        }

        let prefix = firstByte >> 6
        let length = 1 << prefix

        let remaining = self.dropFirst().prefix(length - 1)
        let value = remaining.reduce(UInt64(firstByte & 0x3f)) {
            $0 << 8 + UInt64($1)
        }

        return value
    }
}

extension Array where Element == UInt8 {
    func calculateLongHeaderPacketNumberOffset() throws -> Int {
        guard let first = first, let type = LongPacketType(rawValue: first & LongPacketType.mask) else { throw Errors.InvalidPacket }
        var readerIndex: Int = 5 // First Byte and 4 Byte Version
        readerIndex += self[readerIndex...].varIntPrefixedBytes()!
        readerIndex += self[readerIndex...].varIntPrefixedBytes()!
        // If Initial, then read the token
        if type == .initial {
            readerIndex += self[readerIndex...].varIntPrefixedBytes()!
        }
        // Read Packet Length
        readerIndex += self[readerIndex...].readQuicVarInt()!.bytesRead

        return readerIndex
    }

    func calculateShortHeaderPacketNumberOffset(dcid: ConnectionID) -> Int {
        1 + dcid.length
    }

    mutating func consumeQuicVarIntLengthPrefixedData() -> (value: UInt64, bytes: [UInt8]) {
        if let varInt = self.consumeQuicVarInt() {
            let bytes = Array(self[0..<Int(varInt)])
            self = Array(self[Int(varInt)...])
            return (value: varInt, bytes: bytes)
        } else {
            return (value: 0, bytes: [])
        }
    }

    mutating func consumeQuicVarInt() -> UInt64? {
        // first two bits of the first byte.
        guard self.count >= 1 else { return nil }
        var v = UInt64(self[0])
        let prefix = v >> 6
        let length = (1 << prefix)

        guard self.count >= length else { return nil }

        // Once the length is known, remove these bits and read any remaining bytes.
        v = v & 0x3f
        for i in 1..<length {
            v = (v << 8) + UInt64(self[i])
        }

        self = Array(self[length...])

        return v
    }
}

extension ArraySlice where Element == UInt8 {
    func varIntPrefixedBytes() -> Int? {
        guard let varInt = self.readQuicVarInt() else { return nil }
        return varInt.bytesRead + Int(varInt.value)
    }

    // https://www.rfc-editor.org/rfc/rfc9000.html#name-sample-variable-length-inte
    func readQuicVarInt() -> (bytesRead: Int, value: UInt64)? {

        // first two bits of the first byte.
        guard self.count >= 1 else { return nil }
        var v = UInt64(self[startIndex])
        let prefix = v >> 6
        let length = (1 << prefix)

        guard self.count >= length else { return nil }

        // Once the length is known, remove these bits and read any remaining bytes.
        v = v & 0x3f
        for i in 1..<length {
            v = (v << 8) + UInt64(self[startIndex + i])
        }

        return (length, v)
    }
}
