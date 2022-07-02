//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

import ByteArrayCodable

struct VersionNegotiationHeader: Header {
  var firstByte: FirstByte { .initial }
  var version: Version { Version.negotiation }

  var destinationIDLength: UInt8 { destinationID.length }
  let destinationID: ConnectionID

  var sourceIDLength: UInt8 { sourceID.length }
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
    let encoder = ByteArrayEncoder()
    return versions.flatMap { version in
      try! encoder.encode(version)
    }
  }
}
