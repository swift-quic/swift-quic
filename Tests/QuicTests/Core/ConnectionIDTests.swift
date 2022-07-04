//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

import XCTest
@testable import Quic

final class ConnectionIDTests: XCTestCase {
  func testEmpty() throws {
    XCTAssertEqual(ConnectionID(rawValue: []).length, 0)
  }

  func testMaxLength() throws {
    XCTAssertEqual(ConnectionID.maxLength, Int(ConnectionID.Length.max))
  }

  func testInit() throws {
    let data: [UInt8] = [UInt8](repeating: 0, count: ConnectionID.maxLength)
    XCTAssertEqual(ConnectionID(rawValue: data).length, ConnectionID.Length(ConnectionID.maxLength))
    XCTAssertEqual(ConnectionID(rawValue: data).rawValue, data)
  }

  func testOverflow() throws {
    let data: [UInt8] = [UInt8](repeating: 0, count: ConnectionID.maxLength + 1)
    XCTAssertEqual(data.count, ConnectionID.maxLength + 1)
    XCTAssertEqual(ConnectionID(rawValue: data).length, ConnectionID.Length(ConnectionID.maxLength))
  }
}
