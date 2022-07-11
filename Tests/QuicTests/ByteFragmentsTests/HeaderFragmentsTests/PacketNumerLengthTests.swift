//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

import XCTest
@testable import Quic

final class PacketNumberLengthTests: XCTestCase {
  func testInit() throws {
    XCTAssertEqual(PacketNumberLength(rawValue: 0), ._1)
    XCTAssertEqual(PacketNumberLength(rawValue: 1), ._2)
    XCTAssertEqual(PacketNumberLength(rawValue: 2), ._4)
    XCTAssertEqual(PacketNumberLength(rawValue: 3), ._8)

    XCTAssertNil(PacketNumberLength(rawValue: 4))
    XCTAssertNil(PacketNumberLength(rawValue: UInt8.max))
  }

  func testTruncating() throws {
    XCTAssertEqual(PacketNumberLength(truncatingIfNeeded: 0), ._1)
    XCTAssertEqual(PacketNumberLength(truncatingIfNeeded: 1), ._2)
    XCTAssertEqual(PacketNumberLength(truncatingIfNeeded: 2), ._4)
    XCTAssertEqual(PacketNumberLength(truncatingIfNeeded: 3), ._8)

    XCTAssertEqual(PacketNumberLength(truncatingIfNeeded: 4), ._1)
    XCTAssertEqual(PacketNumberLength(truncatingIfNeeded: 5), ._2)
    XCTAssertEqual(PacketNumberLength(truncatingIfNeeded: 6), ._4)
    XCTAssertEqual(PacketNumberLength(truncatingIfNeeded: 7), ._8)

    XCTAssertEqual(PacketNumberLength(truncatingIfNeeded: UInt8.max - 3), ._1)
    XCTAssertEqual(PacketNumberLength(truncatingIfNeeded: UInt8.max - 2), ._2)
    XCTAssertEqual(PacketNumberLength(truncatingIfNeeded: UInt8.max - 1), ._4)
    XCTAssertEqual(PacketNumberLength(truncatingIfNeeded: UInt8.max), ._8)
  }
}
