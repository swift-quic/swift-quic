//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

enum PacketNumberLength: UInt8 {
  case _1 = 0b00
  case _2 = 0b01
  case _4 = 0b10
  case _8 = 0b11
}

extension PacketNumberLength: ByteFragment {
  static let mask: UInt8 = 0b11
}
