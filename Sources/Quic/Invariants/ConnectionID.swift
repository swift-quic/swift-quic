//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

struct ConnectionID: RawRepresentable {
  let rawValue: [UInt8]
  init(rawValue: [UInt8]) {
    self.rawValue = rawValue
  }
}

extension ConnectionID: Sendable, Hashable {}

extension ConnectionID: Codable {}

