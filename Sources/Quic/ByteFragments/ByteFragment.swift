//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

protocol ByteFragment: RawRepresentable where RawValue == UInt8 {
  static var mask: RawValue { get }
  init(truncatingIfNeeded byte: RawValue)
}

extension ByteFragment {
  init(truncatingIfNeeded byte: RawValue) {
    self.init(rawValue: byte & Self.mask)!
  }
}
