//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

import Foundation
import ByteArrayCodable

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

  static let upperBound: RawValue = 1 << 62
  static var maxRawValue: RawValue { upperBound - 1 }
  static var max: VarInt { VarInt(rawValue: maxRawValue)! }
}

extension VarInt {
  init<S: Sequence>(with bytes: S) where S.Element == UInt8 {
    guard let first = bytes.first(where: { _ in true }) else {
      self.init(rawValue: 0)!
      return
    }

    let prefix = first >> 6
    let length = 1 << prefix

    let remaining = bytes.dropFirst().prefix(length - 1)
    let rawValue = remaining.reduce(UInt64(first & 0x3f)) {
      $0 << 8 + UInt64($1)
    }

    self.init(rawValue: rawValue)!
  }
}

extension VarInt: Sendable, Hashable {}

extension VarInt {
  var bytes: [UInt8] {
    let encoder = ByteArrayEncoder()
    return try! encoder.encode(self)
  }
}

extension VarInt: ContiguousBytes {
  func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
    try bytes.withUnsafeBytes(body)
  }
}

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
      precondition(data < VarInt.upperBound)
      let value = data | 0xc000_0000_0000_0000
      try container.encode(value)
    }
  }

  init(from decoder: Decoder) throws {
    let container = try decoder.singleValueContainer()
    let firstByte = try container.decode(UInt8.self)

    let prefix = firstByte >> 6
    var length = (1 << prefix) - 1

    var bytes = [firstByte]
    while length > 0 {
      bytes.append(try UInt8(from: decoder))
      length -= 1
    }
    self.init(with: bytes)
  }
}
