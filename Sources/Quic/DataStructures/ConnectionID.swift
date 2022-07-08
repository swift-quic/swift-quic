//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

import Foundation

struct ConnectionID: RawRepresentable {
  typealias RawValue = [UInt8]

  private let data: RawValue
  var rawValue: RawValue { data }
  init(rawValue: RawValue) {
    data = rawValue
  }

  var length: Int { data.count }
}

extension ConnectionID {
  init<S: Sequence>(with bytes: S) where S.Element == RawValue.Element {
    self.init(rawValue: RawValue(bytes))
  }
}

extension ConnectionID: Sendable, Hashable, Codable {}

extension ConnectionID: ExpressibleByArrayLiteral {
  init(arrayLiteral elements: RawValue.Element...) {
    self.init(rawValue: elements)
  }
}

extension ConnectionID: ContiguousBytes {
  func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
    try rawValue.withUnsafeBytes(body)
  }
}
