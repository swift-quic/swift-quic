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
