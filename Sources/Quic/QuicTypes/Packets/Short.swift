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

struct GenericShortHeader: ShortHeader, NumberedHeader {
    var firstByte: UInt8
    var destinationID: ConnectionID
    var packetNumber: [UInt8]

    var packetNumberOffset: Int {
        1 + self.destinationID.length
    }

    var bytes: [UInt8] {
        [self.firstByte] + self.destinationID.rawValue + self.packetNumber
    }

    init(firstByte: UInt8, id: ConnectionID, packetNumber: [UInt8]) {
        self.firstByte = firstByte
        self.destinationID = id
        self.packetNumber = packetNumber
    }

    mutating func setPacketNumber(_ pn: [UInt8]) {
        self.packetNumber = pn
    }
}

struct ShortPacket: Packet, NumberedPacket {
    var header: GenericShortHeader
    var payload: [Frame]

    init(header: GenericShortHeader, payload: [Frame]) {
        self.header = header
        self.payload = payload
    }

    var bytes: [UInt8] {
        self.header.bytes + self.serializedPayload
    }
}
