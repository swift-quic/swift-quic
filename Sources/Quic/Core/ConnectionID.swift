//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

struct ConnectionID: RawRepresentable {
  typealias RawValue = [UInt8]
  typealias Length = UInt8

  private let data: RawValue
  var rawValue: RawValue { data }
  init(rawValue: RawValue) {
    guard !rawValue.isEmpty else {
      data = []
      return
    }

    let slice = rawValue[..<ConnectionID.maxLength]
    data = RawValue(slice)
  }

  static var maxLength: Int { Int(Length.max) }
  var length: Length { Length(data.count) }
}

extension ConnectionID: Sendable, Hashable, Codable {}
