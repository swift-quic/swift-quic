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
    let connectionID: ConnectionID = [0, 1, UInt8.max]
    XCTAssertEqual(connectionID.length, 3)
    XCTAssertEqual(connectionID.rawValue, [0, 1, UInt8.max])
  }

  func testContiguousBytes() throws {
    let connectionID: ConnectionID = [0, 1, UInt8.max]
    connectionID.withUnsafeBytes { pointer in
      XCTAssertEqual(pointer.count, 3)
      let bytePointer = pointer.baseAddress!.bindMemory(to: UInt8.self, capacity: 3)
      XCTAssertEqual(bytePointer.pointee, 0)
      XCTAssertEqual(bytePointer.successor().pointee, 1)
      XCTAssertEqual(bytePointer.advanced(by: 2).pointee, UInt8.max)
    }
  }
}
