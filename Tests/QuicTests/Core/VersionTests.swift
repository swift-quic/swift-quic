//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

import XCTest
@testable import Quic

final class VersionTests: XCTestCase {
  func testNegotiation() throws {
    XCTAssertTrue(Version(rawValue: 0).isNegotiation())
    XCTAssertTrue(Version.negotiation.isNegotiation())
  }

  func testVersion1() throws {
    XCTAssertEqual(Version(rawValue: 1), Version.version1)
    XCTAssertFalse(Version.version1.isNegotiation())
  }

  func testReserved() throws {
    XCTAssertTrue(Version(rawValue: 0x0a0a0a0a).isReserved())
    XCTAssertTrue(Version(rawValue: 0x8a8a8a8a).isReserved())
    XCTAssertTrue(Version(rawValue: 0xfafafafa).isReserved())
    XCTAssertFalse(Version.negotiation.isReserved())
    XCTAssertFalse(Version.version1.isReserved())
    XCTAssertFalse(Version(rawValue: 0x0a0a0a).isReserved())
    XCTAssertFalse(Version(rawValue: 0xff0a0a0a).isReserved())
  }
}
