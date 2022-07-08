//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

import XCTest
@testable import Quic

final class StreamFlowDirectionTests: XCTestCase {
  func testInit() throws {
    XCTAssertEqual(StreamFlowDirection(rawValue: 0), .biDirectional)
    XCTAssertEqual(StreamFlowDirection(rawValue: 1), .uniDirectional)

    XCTAssertNil(StreamFlowDirection(rawValue: 2))
    XCTAssertNil(StreamFlowDirection(rawValue: UInt8.max))
  }

  func testTruncating() throws {
    XCTAssertEqual(StreamFlowDirection(truncatingIfNeeded: 0), .biDirectional)
    XCTAssertEqual(StreamFlowDirection(truncatingIfNeeded: 1), .uniDirectional)

    XCTAssertEqual(StreamFlowDirection(truncatingIfNeeded: 2), .biDirectional)
    XCTAssertEqual(StreamFlowDirection(truncatingIfNeeded: 3), .uniDirectional)

    XCTAssertEqual(StreamFlowDirection(truncatingIfNeeded: UInt8.max - 1), .biDirectional)
    XCTAssertEqual(StreamFlowDirection(truncatingIfNeeded: UInt8.max), .uniDirectional)
  }
}
