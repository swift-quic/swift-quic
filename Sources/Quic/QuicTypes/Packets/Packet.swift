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

import Foundation
import NIOCore

protocol Packet: Sendable, CustomStringConvertible {
    associatedtype ConcreteHeader: Header
    var header: ConcreteHeader { get }
    var payload: [Frame] { get }
}

extension Packet {
    var serializedPayload: [UInt8] {
        var buf = ByteBuffer()
        self.payload.forEach { $0.encode(into: &buf) }
        return Array(buf.readableBytesView)
    }

    var type: PacketType {
        PacketType(self)!
    }
}

extension Packet {
    var headerBytes: [UInt8] {
        self.header.bytes
    }

    var description: String {
        return """
        \n--- ✉️ \(self.type) ✉️ ---
        Header: \(self.header)
        Payload [\(self.payload.count) frames]:
            → \(self.payload.map { "\($0)" }.joined(separator: "\n\t→ "))
        ---------------------------
        """
    }
}

protocol NumberedPacket: Packet where ConcreteHeader: NumberedHeader {
    var packetNumber: [UInt8] { get }
}

extension NumberedPacket {
    var packetNumber: [UInt8] {
        self.header.packetNumber
    }
}

extension NumberedPacket {
    func seal(using protector: PacketProtector) throws -> (protectedHeader: [UInt8], encryptedPayload: [UInt8]) {
        // Encrypt the payload
        //print("Encrypting Payload with PacketNumber:\(self.packetNumber) and AuthData:\(self.headerBytes)")
        let encrypted = try protector.encryptPayload(message: self.serializedPayload, packetNumber: self.packetNumber, authenticatingData: self.headerBytes)
        let encryptedPayload = Array(encrypted.ciphertext + encrypted.tag)

        // Protect the header
        let sampleOffset = 4 - self.packetNumber.count
        let sample = Array(encryptedPayload[sampleOffset..<(sampleOffset + protector.sealer!.headerProtector.sampleLength)])
        var protectedHeaderBytes = self.headerBytes
        try protector.applyHeaderProtection(sample: sample, headerBytes: &protectedHeaderBytes, packetNumberOffset: self.header.packetNumberOffset)

        return (protectedHeaderBytes, encryptedPayload)
    }
}

/// https://www.rfc-editor.org/rfc/rfc9000.html#name-sample-packet-number-encodi
func encodePacketNumber(fullPacketNumber fullPN: UInt64, largestAcked: UInt64?) -> [UInt8] {

    // The number of bits must be at least one more
    // than the base-2 logarithm of the number of contiguous
    // unacknowledged packet numbers, including the new packet.
    let numUnacked: UInt64
    if let largestAcked {
        numUnacked = fullPN - largestAcked
    } else {
        numUnacked = fullPN + 1
    }

    let minBits = log2(Double(numUnacked)) + 1
    let numBytes = Int(ceil(minBits / 8))

    // Encode the integer value and truncate to
    // the numBytes least significant bytes.
    return writeQuicVarInt(fullPN).suffix(numBytes)
}

/// https://www.rfc-editor.org/rfc/rfc9000.html#name-sample-packet-number-decodi
func decodePacketNumber(largest: UInt64, truncated: UInt64, nBits: UInt64) -> UInt64 {
    let expected: UInt64 = largest + 1
    let win: UInt64 = 1 << nBits
    let hwin: UInt64 = win / 2
    let mask: UInt64 = win - 1

    // The incoming packet number should be greater than
    // expected_pn - pn_hwin and less than or equal to
    // expected_pn + pn_hwin
    //
    // This means we cannot just strip the trailing bits from
    // expected_pn and add the truncated_pn because that might
    // yield a value outside the window.
    //
    // The following code calculates a candidate value and
    // makes sure it's within the packet number window.
    // Note the extra checks to prevent overflow and underflow.
    let candidate: UInt64 = (expected & ~mask) | truncated
    if (candidate <= expected - hwin) && (candidate < (1 << 62) - win) {
        return candidate + win
    }
    if (candidate > expected + hwin) && (candidate >= win) {
        return candidate - win
    }
    return candidate
}
