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

struct HandshakeHeader: TypedHeader, NumberedHeader {
    let type: LongPacketType = .handshake
    var version: Version

    var destinationIDLength: UInt8 { UInt8(truncatingIfNeeded: self.destinationID.length) }
    let destinationID: ConnectionID

    var sourceIDLength: UInt8 { UInt8(truncatingIfNeeded: self.sourceID.length) }
    let sourceID: ConnectionID

    var packetLength: UInt64
    var packetNumber: [UInt8]

    init(version: Version, destinationID: ConnectionID, sourceID: ConnectionID, packetLength: UInt64 = 0, packetNumber: [UInt8] = []) {
        self.version = version
        self.destinationID = destinationID
        self.sourceID = sourceID
        self.packetLength = packetLength
        self.packetNumber = packetNumber
    }

    var bytes: [UInt8] {
        var bytes = [firstByte]
        bytes += self.version.withUnsafeBytes { Array($0) }
        bytes += self.destinationID.lengthPrefixedBytes
        bytes += self.sourceID.lengthPrefixedBytes
        bytes += writeQuicVarInt(self.packetLength)
        bytes += self.packetNumber
        return bytes
    }

    var packetNumberOffset: Int {
        //self.bytes.count - packetNumber.count
        5 + destinationID.lengthPrefixedBytes.count + sourceID.lengthPrefixedBytes.count + writeQuicVarInt(packetLength).count
    }

    mutating func setPacketNumber(_ pn: [UInt8]) {
        let previousPacketNumberLength = self.packetNumber.count
        self.packetNumber = pn
        self.packetLength += UInt64(pn.count - previousPacketNumberLength)
    }

    mutating func setPacketLength(_ pl: UInt64) {
        self.packetLength = pl
    }
}

struct HandshakePacket: Packet, NumberedPacket {
    var header: HandshakeHeader
    var payload: [Frame] {
        didSet {
            let tagLength = 16
            self.header.setPacketLength(UInt64(serializedPayload.count + tagLength + self.header.packetNumber.count))
        }
    }

    init(header: HandshakeHeader, payload: [Frame]) {
        self.header = header
        self.payload = payload

        // Make sure to propagate the payload length to the header
        let tagLength = 16
        self.header.setPacketLength(UInt64(serializedPayload.count + tagLength + header.packetNumber.count))
    }

    init(version: Version, destinationID: ConnectionID, sourceID: ConnectionID, packetNumber: [UInt8]) {
        let header = HandshakeHeader(
            version: version,
            destinationID: destinationID,
            sourceID: sourceID,
            packetNumber: packetNumber
        )
        self.init(header: header, payload: [])
    }
}

extension HandshakePacket {
    func bytes(suppressingDCID: Bool = false) -> [UInt8] {
        var bytes: [UInt8] = []
        bytes.append(self.header.firstByte)
        bytes.append(contentsOf: self.header.version.bytes)
        if suppressingDCID {
            bytes.append(0x00)
        } else {
            bytes.append(contentsOf: writeQuicVarInt(UInt64(self.header.destinationIDLength)))
            bytes.append(contentsOf: self.header.destinationID.rawValue)
        }
        bytes.append(contentsOf: writeQuicVarInt(UInt64(self.header.sourceIDLength)))
        bytes.append(contentsOf: self.header.sourceID.rawValue)
        bytes.append(contentsOf: writeQuicVarInt(UInt64(Int(self.header.packetNumberLengthByteCount) + self.payload.count + 16), minBytes: 2)) //add 16 here for the encryption tag
        bytes.append(contentsOf: self.header.packetNumber)
        return bytes
    }
}
