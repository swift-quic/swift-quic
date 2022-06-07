//  Created by Kenneth Laskoski on 07/06/22.
//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

struct Version: RawRepresentable {
  let rawValue: UInt32
  init(rawValue: UInt32) {
    self.rawValue = rawValue
  }

  func isNegotiation() -> Bool {
    self == Version.negotiation
  }

  func isForcedNegotiation() -> Bool {
    self.rawValue & 0x0f0f0f0f == 0x0a0a0a0a
  }

  func isReservedForFutureUse() -> Bool {
    self.rawValue & 0xFFFF0000 == 0
  }

  static let negotiation = Version(rawValue: 0)
  static let version1 = Version(rawValue: 1)
}

extension Version: Sendable, Hashable {}
