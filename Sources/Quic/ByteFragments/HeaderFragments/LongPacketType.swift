//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

enum LongPacketType: UInt8 {
  case initial = 0b0000_0000
  case zeroRTT = 0b0001_0000
  case handshake = 0b0010_0000
  case retry = 0b0011_0000
}

extension LongPacketType: ByteFragment {
  static let mask: UInt8 = 0b0011_0000
}
