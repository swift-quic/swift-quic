//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

enum PacketType {
  case notQuic
  case short
  case initial
  case zeroRTT
  case handshake
  case retry

  init(from byte: FirstByte) {
    guard byte.contains(.quic) else {
      self = .notQuic
      return
    }
    guard byte.contains(.long) else {
      self = .short
      return
    }
    if byte.contains(.retry) {
      self = .retry
      return
    }
    if byte.contains(.handshake) {
      self = .handshake
      return
    }
    if byte.contains(.zeroRTT) {
      self = .zeroRTT
      return
    }
    self = .initial
  }
}
