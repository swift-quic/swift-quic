//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

enum LongPacketType: FirstByte {
  case initial = 0b11000000
  case zeroRTT = 0b11010000
  case handshake = 0b11100000
  case retry = 0b11110000
}

enum PacketType {
  case notQuic
  case short
  case long(LongPacketType)

  init(from byte: FirstByte) {
    guard byte.contains(.quic) else {
      self = .notQuic
      return
    }
    guard byte.contains(.long) else {
      self = .short
      return
    }
    let longType = LongPacketType(rawValue: byte)
    self = .long(longType ?? .initial)
  }
}

extension PacketType: CustomStringConvertible {
  var description: String {
    switch self {
    case .notQuic:
      return "Not quic"
    case .short:
      return "1-RTT"
    case .long(let longPacketType):
      switch longPacketType {
      case .initial:
        return "Initial"
      case .zeroRTT:
        return "0-RTT"
      case .handshake:
        return "Handshake"
      case .retry:
        return "Retry"
      }
    }
  }
}

protocol Packet: Sendable, Hashable, Codable {
  associatedtype HeaderType: Header
  var header: HeaderType { get }
  var payload: [UInt8] { get }
}
