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

struct VersionNegotiationHeader: LongHeader {
    var firstByte: UInt8 { HeaderForm.long.rawValue | QuicBit.yes.rawValue | LongPacketType.initial.rawValue }
    var version: Version { Version.negotiation }

    var destinationIDLength: UInt8 { UInt8(truncatingIfNeeded: self.destinationID.length) }
    let destinationID: ConnectionID

    var sourceIDLength: UInt8 { UInt8(truncatingIfNeeded: self.sourceID.length) }
    let sourceID: ConnectionID

    var bytes: [UInt8] {
        var bytes = [firstByte]
        bytes += self.version.withUnsafeBytes { Array($0) }
        bytes += self.destinationID.lengthPrefixedBytes
        bytes += self.sourceID.lengthPrefixedBytes
        return bytes
    }
}

struct VersionNegotiationPacket: Packet {
    let header: VersionNegotiationHeader
    let versions: [Version]

    /// This initializer is intended for outbound Version Negotiation Packets (auto fills the supported versions).
    init(destinationID: ConnectionID, sourceID: ConnectionID) {
        self.header = VersionNegotiationHeader(
            destinationID: destinationID,
            sourceID: sourceID
        )
        self.versions = supportedVersions
    }

    /// This initializer is intended for Decoding inbound Version Negotiation Packets.
    init(destinationID: ConnectionID, sourceID: ConnectionID, supportedVersions: [Version]) {
        self.header = VersionNegotiationHeader(
            destinationID: destinationID,
            sourceID: sourceID
        )
        self.versions = supportedVersions
    }

    var payload: [Frame] {
        return self.versions.map { version in
            Frames.Raw(bytes: version.withUnsafeBytes { Array($0) })
        }
    }
}
