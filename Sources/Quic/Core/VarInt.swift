//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

struct VarInt: RawRepresentable {
  typealias RawValue = UInt64
  static let max: RawValue = 0x3FFFFFFFFFFFFFFF

  private let data: RawValue

  public var rawValue: RawValue { data }
  init?(rawValue: RawValue) {
    guard rawValue <= VarInt.max else {
      return nil
    }
    data = rawValue
  }
}

extension VarInt: Sendable, Hashable, Codable {}
