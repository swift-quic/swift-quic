//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

enum QuicBit: UInt8 {
  case not = 0b0000_0000
  case yes = 0b0100_0000
}

extension QuicBit: ByteFragment {
  static let mask: UInt8 = 0b0100_0000
}
