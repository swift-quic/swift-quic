//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

import XCTest
@testable import Quic

final class PacketTypeTests: XCTestCase {
  func testPacketType() throws {
    for byte in UInt8.min...UInt8.max {
      let firstByte = FirstByte(rawValue: byte)
      let packetType = packetType(from: firstByte)

      XCTAssertTrue(firstByte.contains(.quic) || packetType == .notQuic)
      XCTAssertFalse(firstByte.contains(.quic) && packetType == .notQuic)

      XCTAssertTrue(packetType == .notQuic || firstByte.contains(.long) || packetType == .oneRTT)
      XCTAssertFalse(firstByte.contains(.long) && packetType == .oneRTT)

      XCTAssertTrue(!firstByte.contains(.retry) || packetType == .retry)
      XCTAssertFalse(!firstByte.contains(.retry) && packetType == .retry)

      XCTAssertTrue(packetType == .retry || !firstByte.contains(.handshake) || packetType == .handshake)
      XCTAssertFalse(packetType != .retry && !firstByte.contains(.handshake) && packetType == .handshake)

      XCTAssertTrue(packetType == .retry || !firstByte.contains(.zeroRTT) || packetType == .zeroRTT)
      XCTAssertFalse(packetType != .retry && !firstByte.contains(.zeroRTT) && packetType == .zeroRTT)

      XCTAssertTrue(packetType == .retry || packetType == .handshake || packetType == .zeroRTT || !firstByte.contains(.initial) || packetType == .initial)
      XCTAssertFalse(packetType != .retry && packetType != .handshake && packetType != .zeroRTT && !firstByte.contains(.initial) && packetType == .initial)
    }
  }
}
