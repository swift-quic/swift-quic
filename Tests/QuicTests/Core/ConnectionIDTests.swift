//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

import XCTest
@testable import Quic

final class ConnectionIDTests: XCTestCase {
  func testEmpty() throws {
    let connectionID: ConnectionID = []
    XCTAssertEqual(connectionID.length, 0)
    XCTAssertEqual(connectionID.rawValue, [])
  }

  func testNonEmpty() throws {
    let connectionID: ConnectionID = [0, 1, 2, 3]
    XCTAssertEqual(connectionID.length, 4)
    XCTAssertEqual(connectionID.rawValue, [0, 1, 2, 3])
  }

  func testMaxLength() throws {
    XCTAssertEqual(ConnectionID.maxLength, Int(ConnectionID.Length.max))
  }

  func testInitWithMaxLength() throws {
    let data: [UInt8] = [UInt8](repeating: 0, count: ConnectionID.maxLength)
    let connectionID = ConnectionID(truncating: data)
    XCTAssertEqual(connectionID.length, ConnectionID.Length(ConnectionID.maxLength))
    XCTAssertEqual(connectionID.rawValue, data)
  }

  func testOverflow() throws {
    let data: [UInt8] = [UInt8](repeating: 0, count: ConnectionID.maxLength + 1)
    XCTAssertTrue(data.count > ConnectionID.maxLength)
    XCTAssertNil(ConnectionID(rawValue: data))

    let connectionID = ConnectionID(truncating: data)
    XCTAssertEqual(connectionID.length, ConnectionID.Length(ConnectionID.maxLength))
    XCTAssertEqual(connectionID.rawValue, data.dropLast())
  }
}
