//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

import XCTest
@testable import Quic

final class QuicBitTests: XCTestCase {
  func testInit() throws {
    XCTAssertEqual(QuicBit(rawValue: 0b0000_0000), .not)
    XCTAssertEqual(QuicBit(rawValue: 0b0100_0000), .yes)

    XCTAssertNil(QuicBit(rawValue: 1))
    XCTAssertNil(QuicBit(rawValue: UInt8.max))
  }

  func testTruncating() throws {
    XCTAssertEqual(QuicBit(truncatingIfNeeded: 0), .not)
    XCTAssertEqual(QuicBit(truncatingIfNeeded: 1), .not)
    XCTAssertEqual(QuicBit(truncatingIfNeeded: 0b0100_0000), .yes)
    XCTAssertEqual(QuicBit(truncatingIfNeeded: UInt8.max), .yes)
  }
}
