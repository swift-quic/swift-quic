//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

struct VersionNegotiationHeader: Header {
  var form: HeaderForm { HeaderForm.long }
  var version: Version { Version.negotiation }

  var destinationIDLength: UInt8 { destinationID.length }
  let destinationID: ConnectionID

  var sourceIDLength: UInt8 { sourceID.length }
  let sourceID: ConnectionID
}

struct VersionNegotiationPacket: Packet {
  let header: VersionNegotiationHeader
  let payload: [UInt8]

  init(destinationID: ConnectionID, sourceID: ConnectionID, versions: [Version]) {
    header = VersionNegotiationHeader(
      destinationID: destinationID,
      sourceID: sourceID
    )

    payload = versions.flatMap {
      version in
      withUnsafeBytes(of: version.rawValue.bigEndian) { $0.map { $0 } }
    }
  }
}
