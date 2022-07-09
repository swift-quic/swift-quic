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
    XCTAssertTrue(isReserved(version: Version(rawValue: 0x0a1a3a7a)))
    XCTAssertTrue(isReserved(version: Version(rawValue: 0xfafafafa)))
  }

  func testQuicType() throws {
    let version1: Version = 1
    version1.withUnsafeBytes { rawPointer in
      let buffer = [UInt8](rawPointer)
      buffer.withUnsafeBufferPointer { pointer in
        XCTAssertEqual(Version(with: pointer), version1)
      }
    }
  }
}
