//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

struct VersionNegotiationHeader: LongHeader {
  var firstByte: UInt8 { HeaderForm.long.rawValue | QuicBit.yes.rawValue | LongPacketType.initial.rawValue }
  var version: Version { Version.negotiation }

  var destinationIDLength: UInt8 { UInt8(truncatingIfNeeded: destinationID.length) }
  let destinationID: ConnectionID

  var sourceIDLength: UInt8 { UInt8(truncatingIfNeeded: sourceID.length) }
  let sourceID: ConnectionID
}

struct VersionNegotiationPacket: Packet {
  let header: VersionNegotiationHeader
  let versions: [Version]

  init(destinationID: ConnectionID, sourceID: ConnectionID) {
    header = VersionNegotiationHeader(
      destinationID: destinationID,
      sourceID: sourceID
    )
    versions = supportedVersions
  }

  var payload: [UInt8] {
    return versions.flatMap { version in
      version.withUnsafeBytes { $0 }
    }
  }
}
