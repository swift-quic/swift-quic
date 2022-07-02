//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

import ByteArrayCodable

struct InitialHeader: Header {
  var firstByte: FirstByte { .initial }
  var version: Version { currentVersion }

  var destinationIDLength: UInt8 { destinationID.length }
  let destinationID: ConnectionID

  var sourceIDLength: UInt8 { sourceID.length }
  let sourceID: ConnectionID
}

struct InitialPacket: Packet {
  let header: InitialHeader

  init(destinationID: ConnectionID, sourceID: ConnectionID) {
    header = InitialHeader(
      destinationID: destinationID,
      sourceID: sourceID
    )
  }

  var payload: [UInt8] { [] }
}
