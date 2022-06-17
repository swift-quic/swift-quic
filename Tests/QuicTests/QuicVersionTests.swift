//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

import XCTest
@testable import Quic

final class VersionTests: XCTestCase {
  func testNegoctiation() throws {
    XCTAssertTrue(Version(rawValue: 0).isNegotiation())
    XCTAssertTrue(Version.negotiation.isNegotiation())
  }

  func testVersion1() throws {
    XCTAssertEqual(Version(rawValue: 1), Version.version1)
    XCTAssertFalse(Version.version1.isNegotiation())
  }

  func testForcedNegoctiation() throws {
    XCTAssertTrue(Version(rawValue: 0x0a0a0a0a).isForcedNegotiation())
    XCTAssertTrue(Version(rawValue: 0x8a8a8a8a).isForcedNegotiation())
    XCTAssertTrue(Version(rawValue: 0xfafafafa).isForcedNegotiation())
    XCTAssertFalse(Version.negotiation.isForcedNegotiation())
    XCTAssertFalse(Version.version1.isForcedNegotiation())
    XCTAssertFalse(Version(rawValue: 0x0a0a0a).isForcedNegotiation())
    XCTAssertFalse(Version(rawValue: 0xff0a0a0a).isForcedNegotiation())
  }

  func testReservedForFutureUse() throws {
    XCTAssertTrue(Version(rawValue: 0x10000).isReservedForFutureUse())
    XCTAssertTrue(Version(rawValue: 0x18888).isReservedForFutureUse())
    XCTAssertTrue(Version(rawValue: 0x1ffff).isReservedForFutureUse())
    XCTAssertTrue(Version(rawValue: 0xffff0000).isReservedForFutureUse())
    XCTAssertFalse(Version.negotiation.isReservedForFutureUse())
    XCTAssertFalse(Version.version1.isReservedForFutureUse())
    XCTAssertFalse(Version(rawValue: 0xffff).isReservedForFutureUse())
  }
}
