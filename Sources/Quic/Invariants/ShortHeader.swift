//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

struct ShortHeader {
  let form: HeaderForm
  let destinationID: ConnectionID
  let data: [UInt8]
}

extension ShortHeader: Sendable, Hashable {}

extension ShortHeader: Codable {}
