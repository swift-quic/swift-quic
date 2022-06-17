//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

import XCTest
@testable import Quic

final class HeaderFormTests: XCTestCase {
  func testShort() throws {
    let short = HeaderForm(rawValue: 0)
    XCTAssertTrue(short.isShort())
    XCTAssertFalse(short.isLong())
  }

  func testLong() throws {
    let long = HeaderForm(rawValue: 0b10000000)
    XCTAssertTrue(long.isLong())
    XCTAssertFalse(long.isShort())
  }
}
