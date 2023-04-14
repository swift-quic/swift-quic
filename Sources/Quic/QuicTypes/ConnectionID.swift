//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

struct ConnectionID: RawRepresentable {
  typealias RawValue = [UInt8]

  private let data: RawValue
  var rawValue: RawValue { data }
  init(rawValue: RawValue) {
    data = rawValue
  }

  var length: Int { data.count }
  
  /// Returns the ConnectionID's raw value prefixed with it's byte length as a UVarInt
  var lengthPrefixedBytes:[UInt8] {
    if length == 0 { return [0x00] }
    return writeQuicVarInt(UInt64(self.length)) + self.data
  }
}

extension ConnectionID: ExpressibleByArrayLiteral {
  init(arrayLiteral elements: RawValue.Element...) {
    self.init(rawValue: elements)
  }
}

extension ConnectionID: QuicType {
  init<S>(with bytes: S) where S: Sequence, S.Element == UInt8 {
    self.init(rawValue: RawValue(bytes))
  }

  func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
    try rawValue.withUnsafeBytes(body)
  }
}

extension ConnectionID: Codable {}
