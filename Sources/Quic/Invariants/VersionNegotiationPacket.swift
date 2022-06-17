//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

struct VersionNegotiationPacket: Packet {
  let header: Header
  let payload: [UInt8]

  init(destinationID: ConnectionID, sourceID: ConnectionID, versions: [Version]) {
    header = LongHeader(
      form: HeaderForm(rawValue: 0b10000000),
      version: Version.negotiation,
      destinationIDLength: destinationID.length,
      destinationID: destinationID,
      sourceIDLength: sourceID.length,
      sourceID: sourceID
    )

    payload = versions.flatMap {
      version in
      withUnsafeBytes(of: version.rawValue.bigEndian) { $0.map { $0 } }
    }
  }
}
