//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

import XCTest
@testable import Quic

final class HeaderFormTests: XCTestCase {
  func testLong() throws {
    XCTAssertTrue(HeaderForm.long.isLong())
    XCTAssertFalse(HeaderForm.long.isShort())
  }

  func testShort() throws {
    XCTAssertTrue(HeaderForm.short.isShort())
    XCTAssertFalse(HeaderForm.short.isLong())
  }
}
