//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

struct LongHeader: Header {
  let form: HeaderForm
  let version: Version
  let destinationIDLength: UInt8
  let destinationID: ConnectionID
  let sourceIDLength: UInt8
  let sourceID: ConnectionID
}

extension LongHeader: Sendable, Hashable {}

extension LongHeader: Codable {}
