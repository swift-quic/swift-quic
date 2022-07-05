//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

struct VarInt: RawRepresentable {
  typealias RawValue = UInt64

  private let data: RawValue
  public var rawValue: RawValue { data }
  init?(rawValue: RawValue) {
    guard rawValue < VarInt.upperBound else {
      return nil
    }
    data = rawValue
  }

  static let upperBound: RawValue = 0x4000_0000_0000_0000
  static var max: RawValue { upperBound - 1 }
}

extension VarInt: Sendable, Hashable {}

extension VarInt: Codable {
  func encode(to encoder: Encoder) throws {
    var container = encoder.singleValueContainer()
    switch data {
    case ..<0x40:
      let value = UInt8(exactly: data)!
      try container.encode(value)
    case 0x40..<0x4000:
      let value = UInt16(exactly: data)! | 0x4000
      try container.encode(value)
    case 0x4000..<0x4000_0000:
      let value = UInt32(exactly: data)! | 0x8000_0000
      try container.encode(value)
    default:
      let value = data | 0xc000_0000_0000_0000
      try container.encode(value)
    }
  }

  init(from decoder: Decoder) throws {
    let firstByte = try UInt8(from: decoder)

    let prefix = firstByte >> 6
    var length = 1 << prefix

    var value = UInt64(firstByte) & 0x3f

    while length > 1 {
      value = (value << 8) + UInt64(try UInt8(from: decoder))
      length -= 1
    }
    self.init(rawValue: value)!
  }
}
