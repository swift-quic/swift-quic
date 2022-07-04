//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

import XCTest
@testable import Quic

final class PacketTypeTests: XCTestCase {
  func testAllBytes() throws {
    let allBytes: ClosedRange<UInt8> = UInt8.min...UInt8.max
    XCTAssertTrue(allBytes.contains(0))
    XCTAssertTrue(allBytes.contains(255))
    for byte in allBytes {
      let firstByte = FirstByte(rawValue: byte)
      let packetType = PacketType(from: firstByte)

      XCTAssertTrue(firstByte.contains(.quic) || packetType == .notQuic)
      XCTAssertFalse(firstByte.contains(.quic) && packetType == .notQuic)

      XCTAssertTrue(firstByte.contains(.long) || packetType == .notQuic || packetType == .short)
      XCTAssertFalse(firstByte.contains(.long) && packetType == .short)

      XCTAssertTrue(firstByte.contains(.retry) || packetType != .retry)
      XCTAssertFalse(firstByte.contains(.retry) && packetType != .retry)

      XCTAssertTrue(firstByte.contains(.handshake) || packetType != .handshake)
      XCTAssertFalse(firstByte.contains(.handshake) && packetType != .retry && packetType != .handshake)

      XCTAssertTrue(firstByte.contains(.zeroRTT) || packetType != .zeroRTT)
      XCTAssertFalse(firstByte.contains(.zeroRTT) && packetType != .retry && packetType != .zeroRTT)

      XCTAssertTrue(firstByte.contains(.initial) || packetType != .initial)
      XCTAssertFalse(firstByte.contains(.initial) && packetType != .retry && packetType != .zeroRTT && packetType != .handshake && packetType != .initial)
    }
  }
}
