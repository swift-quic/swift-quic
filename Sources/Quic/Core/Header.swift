//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

protocol Header: Sendable, Hashable, Codable {
  var firstByte: FirstByte { get }
}

protocol LongHeader: Header {
  var version: Version { get }
  var destinationIDLength: ConnectionID.Length { get }
  var destinationID: ConnectionID { get }
  var sourceIDLength: ConnectionID.Length { get }
  var sourceID: ConnectionID { get }
}

protocol ShortHeader: Header {
  var destinationID: ConnectionID { get }
}
