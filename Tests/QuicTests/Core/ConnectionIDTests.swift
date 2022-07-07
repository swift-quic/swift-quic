//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

import XCTest
@testable import Quic

final class ConnectionIDTests: XCTestCase {
  func testMaxLength() throws {
    XCTAssertEqual(ConnectionID.maxLength, Int(ConnectionID.Length.max))

    let data: [UInt8] = [UInt8](repeating: 0, count: ConnectionID.maxLength)
    let connectionID = ConnectionID(rawValue: data)
    XCTAssertEqual(connectionID?.length, ConnectionID.Length(ConnectionID.maxLength))
    XCTAssertEqual(connectionID?.rawValue, data)
  }

  func testTruncating() throws {
    let data: [UInt8] = [UInt8](repeating: 0, count: ConnectionID.maxLength + 1)
    XCTAssertTrue(data.count > ConnectionID.maxLength)
    XCTAssertNil(ConnectionID(rawValue: data))

    let connectionID = ConnectionID(truncatingIfNeeded: data)
    XCTAssertEqual(connectionID.length, ConnectionID.Length(ConnectionID.maxLength))
    XCTAssertEqual(connectionID.rawValue, data.dropLast())
  }

  func testEmptyLiteral() throws {
    let connectionID: ConnectionID = []
    XCTAssertEqual(connectionID.length, 0)
    XCTAssertEqual(connectionID.rawValue, [])
  }

  func testNonEmptyLiteral() throws {
    let connectionID: ConnectionID = [0]
    XCTAssertEqual(connectionID.length, 1)
    XCTAssertEqual(connectionID.rawValue, [0])
  }

}
