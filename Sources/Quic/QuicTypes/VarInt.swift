//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

struct VarInt: RawRepresentable {
  typealias RawValue = UInt64

  private let buffer: [UInt8]
  private let data: RawValue
  public var rawValue: RawValue { data }
  init?(rawValue: RawValue) {
    guard rawValue < VarInt.upperBound else {
      return nil
    }

    switch rawValue {
    case ..<0x40:
      let value = UInt8(exactly: rawValue)!
      buffer = bytes(of: value)
    case 0x40..<0x4000:
      let value = UInt16(exactly: rawValue)! | 0x4000
      buffer = bytes(of: value)
    case 0x4000..<0x4000_0000:
      let value = UInt32(exactly: rawValue)! | 0x8000_0000
      buffer = bytes(of: value)
    default:
      precondition(rawValue < VarInt.upperBound)
      let value = rawValue | 0xc000_0000_0000_0000
      buffer = bytes(of: value)
    }

    data = rawValue
  }

  static let upperBound: RawValue = 1 << 62
  static var maxRawValue: RawValue { upperBound - 1 }
  static var max: VarInt { VarInt(rawValue: maxRawValue)! }
}

extension VarInt: ExpressibleByIntegerLiteral {
  init(integerLiteral value: RawValue) {
    precondition(value < VarInt.upperBound)
    self.init(rawValue: value)!
  }
}

extension VarInt: QuicType {
  init<S: Sequence>(with bytes: S) where S.Element == UInt8 {
    guard let firstByte = bytes.first(where: { _ in true }) else {
      self = 0
      return
    }

    let prefix = firstByte >> 6
    let length = 1 << prefix

    let remaining = bytes.dropFirst().prefix(length - 1)
    let value = remaining.reduce(UInt64(firstByte & 0x3f)) {
      $0 << 8 + UInt64($1)
    }

    self.init(integerLiteral: value)
  }

  func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
    try buffer.withUnsafeBytes(body)
  }
}

func bytes<T>(of value: T) -> [UInt8] where T: FixedWidthInteger {
  withUnsafeBytes(of: value.bigEndian) { $0.map { $0 } }
}
