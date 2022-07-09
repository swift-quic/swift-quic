//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

import XCTest
@testable import Quic

final class HeaderFormTests: XCTestCase {
  func testInit() throws {
    XCTAssertEqual(HeaderForm(rawValue: 0b0000_0000), .short)
    XCTAssertEqual(HeaderForm(rawValue: 0b1000_0000), .long)

    XCTAssertNil(HeaderForm(rawValue: 1))
    XCTAssertNil(HeaderForm(rawValue: UInt8.max))
  }

  func testTruncating() throws {
    XCTAssertEqual(HeaderForm(truncatingIfNeeded: 0), .short)
    XCTAssertEqual(HeaderForm(truncatingIfNeeded: 1), .short)
    XCTAssertEqual(HeaderForm(truncatingIfNeeded: 0x80), .long)
    XCTAssertEqual(HeaderForm(truncatingIfNeeded: UInt8.max), .long)
  }
}
