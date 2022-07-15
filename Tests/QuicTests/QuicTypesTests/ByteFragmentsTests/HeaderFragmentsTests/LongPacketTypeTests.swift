//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

import XCTest
@testable import Quic

final class LongPacketTypeTests: XCTestCase {
  func testInit() throws {
    XCTAssertEqual(LongPacketType(rawValue: 0x00), .initial)
    XCTAssertEqual(LongPacketType(rawValue: 0x10), .zeroRTT)
    XCTAssertEqual(LongPacketType(rawValue: 0x20), .handshake)
    XCTAssertEqual(LongPacketType(rawValue: 0x30), .retry)

    XCTAssertNil(LongPacketType(rawValue: 0x01))
    XCTAssertNil(LongPacketType(rawValue: 0x11))
    XCTAssertNil(LongPacketType(rawValue: 0x21))
    XCTAssertNil(LongPacketType(rawValue: 0x31))

    XCTAssertNil(LongPacketType(rawValue: 0x02))
    XCTAssertNil(LongPacketType(rawValue: 0x12))
    XCTAssertNil(LongPacketType(rawValue: 0x22))
    XCTAssertNil(LongPacketType(rawValue: 0x32))

    XCTAssertNil(LongPacketType(rawValue: 0x04))
    XCTAssertNil(LongPacketType(rawValue: 0x14))
    XCTAssertNil(LongPacketType(rawValue: 0x24))
    XCTAssertNil(LongPacketType(rawValue: 0x34))

    XCTAssertNil(LongPacketType(rawValue: 0x08))
    XCTAssertNil(LongPacketType(rawValue: 0x18))
    XCTAssertNil(LongPacketType(rawValue: 0x28))
    XCTAssertNil(LongPacketType(rawValue: 0x38))

    XCTAssertNil(LongPacketType(rawValue: 0x0f))
    XCTAssertNil(LongPacketType(rawValue: 0x1f))
    XCTAssertNil(LongPacketType(rawValue: 0x2f))
    XCTAssertNil(LongPacketType(rawValue: 0x3f))

    XCTAssertNil(LongPacketType(rawValue: 0x40))
    XCTAssertNil(LongPacketType(rawValue: 0x50))
    XCTAssertNil(LongPacketType(rawValue: 0x60))
    XCTAssertNil(LongPacketType(rawValue: 0x70))

    XCTAssertNil(LongPacketType(rawValue: UInt8.max))
  }

  func testTruncating() throws {
    XCTAssertEqual(LongPacketType(truncatingIfNeeded: 0x00), .initial)
    XCTAssertEqual(LongPacketType(truncatingIfNeeded: 0x10), .zeroRTT)
    XCTAssertEqual(LongPacketType(truncatingIfNeeded: 0x20), .handshake)
    XCTAssertEqual(LongPacketType(truncatingIfNeeded: 0x30), .retry)

    XCTAssertEqual(LongPacketType(truncatingIfNeeded: 0x01), .initial)
    XCTAssertEqual(LongPacketType(truncatingIfNeeded: 0x11), .zeroRTT)
    XCTAssertEqual(LongPacketType(truncatingIfNeeded: 0x21), .handshake)
    XCTAssertEqual(LongPacketType(truncatingIfNeeded: 0x31), .retry)

    XCTAssertEqual(LongPacketType(truncatingIfNeeded: 0x02), .initial)
    XCTAssertEqual(LongPacketType(truncatingIfNeeded: 0x12), .zeroRTT)
    XCTAssertEqual(LongPacketType(truncatingIfNeeded: 0x22), .handshake)
    XCTAssertEqual(LongPacketType(truncatingIfNeeded: 0x32), .retry)

    XCTAssertEqual(LongPacketType(truncatingIfNeeded: 0x04), .initial)
    XCTAssertEqual(LongPacketType(truncatingIfNeeded: 0x14), .zeroRTT)
    XCTAssertEqual(LongPacketType(truncatingIfNeeded: 0x24), .handshake)
    XCTAssertEqual(LongPacketType(truncatingIfNeeded: 0x34), .retry)

    XCTAssertEqual(LongPacketType(truncatingIfNeeded: 0x08), .initial)
    XCTAssertEqual(LongPacketType(truncatingIfNeeded: 0x18), .zeroRTT)
    XCTAssertEqual(LongPacketType(truncatingIfNeeded: 0x28), .handshake)
    XCTAssertEqual(LongPacketType(truncatingIfNeeded: 0x38), .retry)

    XCTAssertEqual(LongPacketType(truncatingIfNeeded: 0x0f), .initial)
    XCTAssertEqual(LongPacketType(truncatingIfNeeded: 0x1f), .zeroRTT)
    XCTAssertEqual(LongPacketType(truncatingIfNeeded: 0x2f), .handshake)
    XCTAssertEqual(LongPacketType(truncatingIfNeeded: 0x3f), .retry)

    XCTAssertEqual(LongPacketType(truncatingIfNeeded: 0x40), .initial)
    XCTAssertEqual(LongPacketType(truncatingIfNeeded: 0x50), .zeroRTT)
    XCTAssertEqual(LongPacketType(truncatingIfNeeded: 0x60), .handshake)
    XCTAssertEqual(LongPacketType(truncatingIfNeeded: 0x70), .retry)

    XCTAssertEqual(LongPacketType(truncatingIfNeeded: UInt8.max), .retry)
  }
}
