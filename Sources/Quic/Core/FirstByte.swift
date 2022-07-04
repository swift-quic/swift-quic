//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

struct FirstByte: OptionSet {
  typealias RawValue = UInt8

  private let data: RawValue
  var rawValue: RawValue { data }
  init(rawValue: RawValue) {
    data = rawValue
  }

  private static let bit7: FirstByte = 0b1000_0000
  private static let bit6: FirstByte = 0b0100_0000
  private static let bit5: FirstByte = 0b0010_0000
  private static let bit4: FirstByte = 0b0001_0000
  private static let bit3: FirstByte = 0b0000_1000
  private static let bit2: FirstByte = 0b0000_0100
  private static let bit1: FirstByte = 0b0000_0010
  private static let bit0: FirstByte = 0b0000_0001

  static let quic: FirstByte = [.bit6]
  static let long: FirstByte = [.quic, .bit7]

  static let initial: FirstByte = [.long]
  static let zeroRTT: FirstByte = [.long, .bit4]
  static let handshake: FirstByte = [.long, .bit5]
  static let retry: FirstByte = [.long, .bit5, .bit4]

  static let spin: FirstByte = [.quic, .bit5]
  static let keyPhase: FirstByte = [.quic, .bit2]
}

extension FirstByte: Sendable, Hashable, Codable {}

extension FirstByte: ExpressibleByIntegerLiteral {
  init(integerLiteral value: RawValue) {
    self.init(rawValue: value)
  }
}
