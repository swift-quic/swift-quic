//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

struct StreamID: RawRepresentable {
  typealias RawValue = VarInt

  private let data: RawValue
  var rawValue: RawValue { data }
  init(rawValue: RawValue) {
    data = rawValue
  }

  var encodedType: StreamType {
    StreamType(truncatingIfNeeded: StreamType.RawValue(self.rawValue.rawValue))
  }
}

extension StreamID: QuicType {
  init(with bytes: UnsafeBufferPointer<UInt8>) {
    self.init(rawValue: RawValue(with: bytes))
  }

  func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
    try rawValue.withUnsafeBytes(body)
  }
}

extension StreamID: Codable {}
