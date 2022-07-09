//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

enum HeaderForm: UInt8 {
  case short = 0b0000_0000
  case long = 0b1000_0000
}

extension HeaderForm {
  init(truncatingIfNeeded source: RawValue) {
    self.init(rawValue: source & 0b1000_0000)!
  }
}

extension HeaderForm: Sendable, Hashable {}
