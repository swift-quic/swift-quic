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

import NIOCore

/// Copied from Swift-NIO-SSH project
extension ByteBuffer {
    /// A helper block that will rewind the reader index when an error is encountered.
    mutating func rewindReaderOnError<T>(_ body: (inout ByteBuffer) throws -> T) rethrows -> T {
        let oldReaderIndex = self.readerIndex

        do {
            return try body(&self)
        } catch {
            self.moveReaderIndex(to: oldReaderIndex)
            throw error
        }
    }

    /// A helper function that will rewind the reader index when nil is returned.
    mutating func rewindReaderOnNil<T>(_ body: (inout ByteBuffer) -> T?) -> T? {
        let oldReaderIndex = self.readerIndex

        guard let result = body(&self) else {
            self.moveReaderIndex(to: oldReaderIndex)
            return nil
        }

        return result
    }
}

private func itoh(_ value: UInt8) -> UInt8 {
    return (value > 9) ? (charA + value - 10) : (char0 + value)
}

private func htoi(_ value: UInt8) throws -> UInt8 {
    switch value {
        case char0...char0 + 9:
            return value - char0
        case charA...charA + 5:
            return value - charA + 10
        default:
            throw ByteHexEncodingErrors.incorrectHexValue
    }
}

extension ByteBuffer {
    init(hexString: String) throws {
        try self.init(bytes: Array(hexString: hexString))
    }
}

extension ByteBufferView {
    var hexString: String {
        let hexLen = self.count * 2
        let ptr = UnsafeMutablePointer<UInt8>.allocate(capacity: hexLen)
        var offset = 0

        for i in self {
            ptr[Int(offset * 2)] = itoh((i >> 4) & 0xF)
            ptr[Int(offset * 2 + 1)] = itoh(i & 0xF)
            offset += 1
        }

        return String(bytesNoCopy: ptr, length: hexLen, encoding: .utf8, freeWhenDone: true)!
    }
}

extension ByteBuffer {
    func getQuicVarInt(at offset: Int) -> (length: Int, value: UInt64)? {
        // first two bits of the first byte.
        //guard self.readableBytes >= 1 + offset else { print("GetQuicVarInt::Couldn't read first Byte. ReadableBytes: \(self.readableBytes), Offset: \(offset)"); return nil }
        guard let vByte = self.getBytes(at: offset, length: 1)?.first else { print("GetQuicVarInt::Not Enough Bytes Available"); return nil }
        var v = UInt64(vByte)
        let prefix = v >> 6
        let length = (1 << prefix) - 1

        // Make sure we have enough bytes before we start forcefully unwrapping below...
        guard self.readableBytes >= (offset - self.readerIndex) + length else { print("GetQuicVarInt::Not Enough Bytes Available - Offset: \(offset - self.readerIndex) + Length: \(length)"); return nil }

        // Once the length is known, remove these bits and read any remaining bytes.
        v = v & 0x3f
        for i in 0..<length {
            v = (v << 8) + UInt64(self.getBytes(at: offset + i + 1, length: 1)![0])
        }

        return (length + 1, v)
    }

    func getQuicVarIntLengthPrefixedBytes(at offset: Int) -> [UInt8]? {
        guard let varInt = self.getQuicVarInt(at: offset), varInt.value > 0, varInt.value < Int.max, self.readableBytes > Int(varInt.value) + offset else { return nil }
        return self.getBytes(at: offset + varInt.length, length: Int(varInt.value))
    }

    // https://www.rfc-editor.org/rfc/rfc9000.html#name-sample-variable-length-inte
    /// Attempts to read a VarInt from the ByteBuffer
    /// - Returns: The UInt64 representation of the consumed VarInt or nil, if the read failed.
    /// - Note: This method rewinds the ByteBuffers reader index if it fails to consume a VarInt
    mutating func readQuicVarInt() -> UInt64? {
        self.rewindReaderOnNil { `self` in
            // first two bits of the first byte.
            guard self.readableBytes >= 1 else { print("Not enough bytes to begin reading VarInt"); return nil }
            guard let vByte = self.readBytes(length: 1)?.first else { return nil }
            var v = UInt64(vByte)
            let prefix = v >> 6
            let length = (1 << prefix) - 1

            guard self.readableBytes >= length else { print("Not enough VarInt bytes to read entire VarInt"); return nil }

            // Once the length is known, remove these bits and read any remaining bytes.
            v = v & 0x3f
            for _ in 0..<length {
                v = (v << 8) + UInt64(self.readBytes(length: 1)![0])
            }

            return v
        }
    }

    mutating func readQuicVarIntLengthPrefixedBytes() -> [UInt8]? {
        self.rewindReaderOnNil { `self` in
            guard let length = self.readQuicVarInt(), self.readableBytes >= length, length >= 0, length < Int.max else { return nil }
            return self.readBytes(length: Int(length))
        }
    }

    mutating func readQuicVarIntLengthPrefixedBytesReturningVarInt() -> (UInt64, [UInt8])? {
        self.rewindReaderOnNil { `self` -> (UInt64, [UInt8])? in
            guard let length = self.readQuicVarInt(), self.readableBytes >= length, length >= 0, length < Int.max else { return nil }
            guard let bytes = self.readBytes(length: Int(length)) else { return nil }
            return (length, bytes)
        }
    }

    mutating func writeQuicVarInt(_ num: UInt64, minBytes: Int = 0) {
        var bytes: [UInt8] = num.bytes(minBytes: minBytes)
        guard !bytes.isEmpty else { return }

        let length = self.getLength(bytes.count)
        if (bytes[0] >> 6) == 0 && (minBytes <= bytes.count) {
            // encode the length in the two available bits
            bytes[0] ^= (UInt8(length) << 6)
        } else {
            // add a new byte to store the length
            bytes.insert(UInt8(length + 1) << 6, at: 0)
        }
        self.writeBytes(bytes)
    }

    mutating func writeQuicVarIntLengthPrefixedBytes(_ bytes: [UInt8]) {
        self.writeQuicVarInt(UInt64(bytes.count))
        self.writeBytes(bytes)
    }

    /// Attempts to read a VarInt from the ByteBuffer
    /// - Returns: The UInt64 representation of the consumed VarInt or nil, if the read failed.
    /// - Note: This method rewinds the ByteBuffers reader index if it fails to consume a VarInt
    mutating func readVarInt() -> UInt64? {
        self.rewindReaderOnNil { `self` in
            var value: UInt64 = 0
            var shift: UInt64 = 0

            while true {
                guard let c: UInt8 = self.readInteger() else {
                    // ran out of bytes. Reset the read pointer and return nil.
                    return nil
                }

                value |= UInt64(c & 0x7F) << shift
                if c & 0x80 == 0 {
                    return value
                }
                shift += 7
                if shift > 63 {
                    print("Invalid varint, requires shift (\(shift)) > 64")
                    return nil
                }
            }
        }
    }

    mutating func writeVarInt(_ v: Int) {
        var value = v
        while true {
            if (value & ~0x7F) == 0 {
                // final byte
                self.writeInteger(UInt8(truncatingIfNeeded: value))
                return
            } else {
                self.writeInteger(UInt8(value & 0x7F) | 0x80)
                value = value >> 7
            }
        }
    }

    private func getLength(_ bytes: Int) -> UInt8 {
        switch bytes {
            case 1: return 0
            case 2: return 1
            case 3, 4: return 2
            case 5...8: return 3
            default: return 0
        }
    }
}
