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

struct InitialHeader: TypedHeader, NumberedHeader {
    let type: LongPacketType = .initial
    var version: Version

    var destinationIDLength: UInt8 { UInt8(truncatingIfNeeded: self.destinationID.length) }
    let destinationID: ConnectionID

    var sourceIDLength: UInt8 { UInt8(truncatingIfNeeded: self.sourceID.length) }
    let sourceID: ConnectionID

    var token: [UInt8]

    var packetLength: UInt64
    var packetNumber: [UInt8]

    init(version: Version, destinationID: ConnectionID, sourceID: ConnectionID, token: [UInt8] = [], packetLength: UInt64 = 0, packetNumber: [UInt8] = []) {
        self.version = version
        self.destinationID = destinationID
        self.sourceID = sourceID
        self.token = token
        self.packetNumber = packetNumber
        self.packetLength = packetLength
    }

    var bytes: [UInt8] {
        var bytes = [firstByte]
        bytes += self.version.withUnsafeBytes { Array($0) }
        bytes += self.destinationID.lengthPrefixedBytes
        bytes += self.sourceID.lengthPrefixedBytes
        bytes += writeQuicVarInt(UInt64(self.token.count))
        bytes += self.token
        bytes += writeQuicVarInt(self.packetLength)
        bytes += self.packetNumber
        return bytes
    }

    // Magic 5 is first byte + version
    var packetNumberOffset: Int {
        //self.bytes.count - packetNumber.count
        5 + destinationID.lengthPrefixedBytes.count + sourceID.lengthPrefixedBytes.count + 1 + token.count + writeQuicVarInt(packetLength).count
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

struct InitialPacket: Packet, NumberedPacket {
    var header: InitialHeader
    var payload: [any Frame] {
        didSet {
            let tagLength = 16
            self.header.setPacketLength(UInt64(serializedPayload.count + tagLength + self.header.packetNumber.count))
        }
    }

    var packetNumber: [UInt8] { self.header.packetNumber }

    init(header: InitialHeader, payload: [any Frame]) {
        self.header = header
        self.payload = payload
        // Make sure to propagate the payload length to the header
        let tagLength = 16
        self.header.setPacketLength(UInt64(serializedPayload.count + tagLength + header.packetNumber.count))
    }

    init(version: Version, destinationID: ConnectionID, sourceID: ConnectionID, token: [UInt8] = [], packetLength: UInt64 = 0, packetNumber: [UInt8] = []) {
        self.header = InitialHeader(
            version: version,
            destinationID: destinationID,
            sourceID: sourceID,
            token: token,
            packetLength: packetLength,
            packetNumber: packetNumber
        )
        self.payload = []
    }
}

extension InitialPacket {
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
        bytes.append(UInt8(self.header.token.count))
        if !self.header.token.isEmpty {
            bytes.append(contentsOf: self.header.token)
        }
        bytes.append(contentsOf: writeQuicVarInt(UInt64(Int(self.header.packetNumberLengthByteCount) + self.payload.count + 16), minBytes: 0)) //add 16 here for the encryption tag
        bytes.append(contentsOf: self.header.packetNumber)
        return bytes
    }
}
