//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

struct FirstByte: RawRepresentable, OptionSet {
  typealias RawValue = UInt8

  let data: RawValue
  var rawValue: RawValue { data }
  init(rawValue: RawValue) {
    data = rawValue
  }

  static private let bit7: FirstByte = 0b10000000
  static private let bit6: FirstByte = 0b01000000
  static private let bit5: FirstByte = 0b00100000
  static private let bit4: FirstByte = 0b00010000
  static private let bit3: FirstByte = 0b00001000
  static private let bit2: FirstByte = 0b00000100
  static private let bit1: FirstByte = 0b00000010
  static private let bit0: FirstByte = 0b00000001

  static let quic: FirstByte = .bit6
  static let long: FirstByte = .bit7

  static let initial: FirstByte = [.long, .quic]
  static let zeroRTT: FirstByte = [.long, .quic, .bit4]
  static let handshake: FirstByte = [.long, .quic, .bit5]
  static let retry: FirstByte = [.long, .quic, .bit5, .bit4]

  static let oneRTT: FirstByte = [.quic]
  static let spin: FirstByte = [.quic, .bit5]
  static let keyPhase: FirstByte = [.quic, .bit2]
}

extension FirstByte: Sendable, Hashable, Codable {}

extension FirstByte: ExpressibleByIntegerLiteral {
  init(integerLiteral value: RawValue) {
    self.init(rawValue: value)
  }
}
