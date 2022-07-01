//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

struct HeaderForm: RawRepresentable {
  let rawValue: UInt8
  init(rawValue: UInt8) {
    self.rawValue = rawValue
  }

  static let long = HeaderForm(rawValue: 0b10000000)
  static let short = HeaderForm(rawValue: 0)

  func isLong() -> Bool {
    !isShort()
  }

  func isShort() -> Bool {
    rawValue & 0b10000000 == 0
  }
}

extension HeaderForm: Sendable, Hashable {}

extension HeaderForm: Codable {}
