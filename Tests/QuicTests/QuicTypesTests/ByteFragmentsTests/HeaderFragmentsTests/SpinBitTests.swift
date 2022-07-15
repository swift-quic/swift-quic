//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

import XCTest
@testable import Quic

final class SpinBitTests: XCTestCase {
  func testInit() throws {
    XCTAssertEqual(SpinBit(rawValue: 0b0000_0000), .not)
    XCTAssertEqual(SpinBit(rawValue: 0b0010_0000), .yes)

    XCTAssertNil(SpinBit(rawValue: 1))
    XCTAssertNil(SpinBit(rawValue: UInt8.max))
  }

  func testTruncating() throws {
    XCTAssertEqual(SpinBit(truncatingIfNeeded: 0), .not)
    XCTAssertEqual(SpinBit(truncatingIfNeeded: 1), .not)
    XCTAssertEqual(SpinBit(truncatingIfNeeded: 0b0010_0000), .yes)
    XCTAssertEqual(SpinBit(truncatingIfNeeded: UInt8.max), .yes)
  }
}
