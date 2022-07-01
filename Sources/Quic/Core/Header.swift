//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

protocol Header: Sendable, Hashable, Codable {
  var form: HeaderForm { get }
}

protocol LongHeader: Header {
  var version: Version { get }
  var destinationIDLength: UInt8 { get }
  var destinationID: ConnectionID { get }
  var sourceIDLength: UInt8 { get }
  var sourceID: ConnectionID { get }
}

protocol ShortHeader: Header {
  var destinationID: ConnectionID { get }
}

extension Header {
  func isLong() -> Bool { form.isLong() }
  func isShort() -> Bool { form.isShort() }
}
