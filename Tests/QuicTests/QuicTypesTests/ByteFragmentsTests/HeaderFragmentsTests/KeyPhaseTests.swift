//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

import XCTest
@testable import Quic

final class KeyPhaseTests: XCTestCase {
  func testInit() throws {
    XCTAssertEqual(KeyPhase(rawValue: 0b0000_0000), .not)
    XCTAssertEqual(KeyPhase(rawValue: 0b0000_0100), .yes)

    XCTAssertNil(KeyPhase(rawValue: 1))
    XCTAssertNil(KeyPhase(rawValue: UInt8.max))
  }

  func testTruncating() throws {
    XCTAssertEqual(KeyPhase(truncatingIfNeeded: 0), .not)
    XCTAssertEqual(KeyPhase(truncatingIfNeeded: 1), .not)
    XCTAssertEqual(KeyPhase(truncatingIfNeeded: 0b0000_0100), .yes)
    XCTAssertEqual(KeyPhase(truncatingIfNeeded: UInt8.max), .yes)
  }
}
