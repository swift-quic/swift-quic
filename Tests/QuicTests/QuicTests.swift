//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

import XCTest
@testable import Quic

final class QuicTests: XCTestCase {
  func testVersion1() throws {
    XCTAssertEqual(Version(rawValue: 1), .version1)
    XCTAssertFalse(isNegotiation(version: .version1))
    XCTAssertFalse(isReserved(version: .version1))
  }

  func testCurrentVersion() throws {
    XCTAssertEqual(.version1, currentVersion)
    XCTAssertTrue(isKnown(version: currentVersion))
    XCTAssertTrue(isSupported(version: currentVersion))
  }

  func testKnownVersions() throws {
    XCTAssertTrue(isKnown(version: .version2))
    XCTAssertTrue(isKnown(version: .version1))
    XCTAssertTrue(isKnown(version: .versionDraft29))
  }

  func testSupportedVersions() throws {
    // Unsupported Versions
    XCTAssertFalse(isSupported(version: .version2))
    // Supported Versions
    XCTAssertTrue(isSupported(version: .version1))
    XCTAssertTrue(isSupported(version: .versionDraft29))
  }

  func testMinDatagramSize() throws {
    XCTAssertEqual(minDatagramSize, 1200)
  }

  func testMaxConnectionIDLength() throws {
    XCTAssertEqual(maxConnectionIDLength, 20)
  }
}
