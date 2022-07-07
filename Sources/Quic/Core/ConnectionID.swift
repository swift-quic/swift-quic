//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

import Foundation

struct ConnectionID: RawRepresentable {
  typealias RawValue = [UInt8]
  typealias Length = UInt8

  private let data: RawValue
  var rawValue: RawValue { data }
  init?(rawValue: RawValue) {
    guard rawValue.count <= ConnectionID.maxLength else {
      return nil
    }
    data = rawValue
  }

  static var maxLength: Int { Int(Length.max) }
  var length: Length { Length(data.count) }
}

extension ConnectionID {
  init(truncatingIfNeeded source: RawValue) {
    let upperBound = min(ConnectionID.maxLength, source.count)
    let slice = RawValue(source[..<upperBound])
    self.init(rawValue: slice)!
  }
}

extension ConnectionID: Sendable, Hashable, Codable {}

extension ConnectionID: ExpressibleByArrayLiteral {
  init(arrayLiteral elements: RawValue.Element...) {
    self.init(truncatingIfNeeded: elements)
  }
}

extension ConnectionID: ContiguousBytes {
  func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
    try rawValue.withUnsafeBytes(body)
  }
}
