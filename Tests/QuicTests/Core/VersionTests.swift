//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

import XCTest
@testable import Quic

final class VersionTests: XCTestCase {
  func testNegotiation() throws {
    XCTAssertEqual(Version(rawValue: 0), Version.negotiation)
    XCTAssertTrue(isNegotiation(version: .negotiation))
  }

  func testReserved() throws {
    XCTAssertFalse(isReserved(version: .negotiation))
    XCTAssertTrue(isReserved(version: Version(rawValue: 0x0a0a0a0a)))
    XCTAssertTrue(isReserved(version: Version(rawValue: 0x8a8a8a8a)))
    XCTAssertTrue(isReserved(version: Version(rawValue: 0xfafafafa)))
  }
}
