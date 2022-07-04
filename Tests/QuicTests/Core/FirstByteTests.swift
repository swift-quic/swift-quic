//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

import XCTest
@testable import Quic

final class FirstByteTests: XCTestCase {
  func testFirstByte() throws {
    let byte: FirstByte = 0b1111_0000
    XCTAssertTrue(byte.contains(.quic))
    XCTAssertTrue(byte.contains(.long))
    XCTAssertTrue(byte.contains(.initial))
    XCTAssertTrue(byte.contains(.zeroRTT))
    XCTAssertTrue(byte.contains(.handshake))
    XCTAssertTrue(byte.contains(.retry))
    XCTAssertTrue(byte.contains(.spin))
    XCTAssertFalse(byte.contains(.keyPhase))
  }
}
