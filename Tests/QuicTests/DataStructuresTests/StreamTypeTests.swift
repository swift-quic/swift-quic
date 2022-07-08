//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

import XCTest
@testable import Quic

final class StreamTypeTests: XCTestCase {
  func testInit() throws {
    XCTAssertEqual(StreamType(rawValue: 0), .clientBidi)
    XCTAssertEqual(StreamType(rawValue: 1), .serverBidi)
    XCTAssertEqual(StreamType(rawValue: 2), .clientUni)
    XCTAssertEqual(StreamType(rawValue: 3), .serverUni)

    XCTAssertNil(StreamType(rawValue: 4))
    XCTAssertNil(StreamType(rawValue: UInt8.max))
  }

  func testTruncating() throws {
    XCTAssertEqual(StreamType(truncatingIfNeeded: 0), .clientBidi)
    XCTAssertEqual(StreamType(truncatingIfNeeded: 1), .serverBidi)
    XCTAssertEqual(StreamType(truncatingIfNeeded: 2), .clientUni)
    XCTAssertEqual(StreamType(truncatingIfNeeded: 3), .serverUni)

    XCTAssertEqual(StreamType(truncatingIfNeeded: 4), .clientBidi)
    XCTAssertEqual(StreamType(truncatingIfNeeded: 5), .serverBidi)
    XCTAssertEqual(StreamType(truncatingIfNeeded: 6), .clientUni)
    XCTAssertEqual(StreamType(truncatingIfNeeded: 7), .serverUni)

    XCTAssertEqual(StreamType(truncatingIfNeeded: UInt8.max - 3), .clientBidi)
    XCTAssertEqual(StreamType(truncatingIfNeeded: UInt8.max - 2), .serverBidi)
    XCTAssertEqual(StreamType(truncatingIfNeeded: UInt8.max - 1), .clientUni)
    XCTAssertEqual(StreamType(truncatingIfNeeded: UInt8.max), .serverUni)
  }

  func testOrigin() throws {
    XCTAssertEqual(StreamType.clientBidi.origin, .client)
    XCTAssertEqual(StreamType.serverBidi.origin, .server)
    XCTAssertEqual(StreamType.clientUni.origin, .client)
    XCTAssertEqual(StreamType.serverUni.origin, .server)
  }

  func testFlowDirection() throws {
    XCTAssertEqual(StreamType.clientBidi.flowDirection, .biDirectional)
    XCTAssertEqual(StreamType.serverBidi.flowDirection, .biDirectional)
    XCTAssertEqual(StreamType.clientUni.flowDirection, .uniDirectional)
    XCTAssertEqual(StreamType.serverUni.flowDirection, .uniDirectional)
  }
}
