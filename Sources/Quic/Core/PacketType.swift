//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

enum PacketType: UInt8 {
  case notQuic = 0b0000_0000
  case oneRTT = 0b0100_0000
  case initial = 0b1100_0000
  case zeroRTT = 0b1101_0000
  case handshake = 0b1110_0000
  case retry = 0b1111_0000
}

extension PacketType: Sendable, Hashable {}

func packetType(from byte: FirstByte) -> PacketType {
  guard byte.contains(.quic) else {
    return .notQuic
  }

  guard byte.contains(.long) else {
    return .oneRTT
  }

  if byte.contains(.retry) {
    return .retry
  }

  if byte.contains(.handshake) {
    return .handshake
  }

  if byte.contains(.zeroRTT) {
    return .zeroRTT
  }

  return .initial
}
