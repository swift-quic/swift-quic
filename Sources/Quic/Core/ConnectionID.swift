//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

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
  init(truncating rawValue: RawValue) {
    let upperBound = min(ConnectionID.maxLength, rawValue.count)
    let slice = RawValue(rawValue[..<upperBound])
    self.init(rawValue: slice)!
  }
}

extension ConnectionID: Sendable, Hashable, Codable {}

extension ConnectionID: ExpressibleByArrayLiteral {
  init(arrayLiteral elements: RawValue.Element...) {
    self.init(truncating: elements)
  }
}
