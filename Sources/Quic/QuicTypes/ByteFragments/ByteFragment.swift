//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

protocol ByteFragment: Sendable, Hashable, RawRepresentable where RawValue == UInt8 {
  static var mask: RawValue { get }
  init(truncatingIfNeeded source: RawValue)
}

extension ByteFragment {
  init(truncatingIfNeeded source: RawValue) {
    self.init(rawValue: source & Self.mask)!
  }
}
