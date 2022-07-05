//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

enum PacketType {
  case notQuic
  case oneRTT
  case initial
  case zeroRTT
  case handshake
  case retry
}

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
