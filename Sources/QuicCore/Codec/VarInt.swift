//  Created by Kenneth Laskoski on 07/06/22.
//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

enum VarInt: Codable {
  case length1(UInt8)
  case length2(UInt16)
  case length4(UInt32)
  case length8(UInt64)

  static let max1: UInt8 = 0x3F
  static let max2: UInt16 = 0x3FFF
  static let max4: UInt32 = 0x3FFFFFFF
  static let max8: UInt64 = 0x3FFFFFFFFFFFFFFF

  init(rawValue: UInt8) {
    if rawValue <= VarInt.max1 {
      self = .length1(rawValue)
    } else {
      self = .length2(UInt16(rawValue))
    }
  }

  init(rawValue: UInt16) {
    if rawValue <= VarInt.max2 {
      self = .length2(rawValue)
    } else {
      self = .length4(UInt32(rawValue))
    }
  }

  init(rawValue: UInt32) {
    if rawValue <= VarInt.max4 {
      self = .length4(rawValue)
    } else {
      self = .length8(UInt64(rawValue))
    }
  }

  init?(rawValue: UInt64) {
    guard rawValue <= VarInt.max8 else {
      return nil
    }
    self = .length8(rawValue)
  }
}
