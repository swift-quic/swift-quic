//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

struct HeaderForm: RawRepresentable {
  let rawValue: UInt8
  init(rawValue: UInt8) {
    self.rawValue = rawValue
  }

  func isShort() -> Bool {
    rawValue & 0b10000000 == 0
  }

  func isLong() -> Bool {
    !isShort()
  }
}

extension HeaderForm: Sendable, Hashable {}

extension HeaderForm: Codable {}
