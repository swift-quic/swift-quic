//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

import XCTest
@testable import Quic

final class ConnectionIDTests: XCTestCase {
  func testInit() throws {
    let data: [UInt8] = [UInt8](repeating: 0, count: 255)
    let connectionID = ConnectionID(rawValue: data)

    XCTAssertEqual(connectionID.length, 255)
    XCTAssertEqual(connectionID.rawValue, data)
  }

  func testInitWithSequence() throws {
    let data: [UInt8] = [0, 1, UInt8.max - 1, UInt8.max]
    data.withUnsafeBytes { pointer in
      XCTAssertEqual(ConnectionID(with: pointer).rawValue, data)
    }
  }

  func testEmptyLiteral() throws {
    let connectionID: ConnectionID = []
    XCTAssertEqual(connectionID.length, 0)
    XCTAssertEqual(connectionID.rawValue, [])
  }

  func testNonEmptyLiteral() throws {
    let connectionID: ConnectionID = [0, 1, UInt8.max - 1, UInt8.max]
    XCTAssertEqual(connectionID.length, 4)
    XCTAssertEqual(connectionID.rawValue, [0, 1, UInt8.max - 1, UInt8.max])
  }

  func testContiguousBytes() throws {
    let connectionID: ConnectionID = [0, 1, UInt8.max - 1, UInt8.max]
    connectionID.withUnsafeBytes { pointer in
      XCTAssertEqual(pointer.count, connectionID.length)

      let bytePointer = pointer.baseAddress!.bindMemory(to: UInt8.self, capacity: pointer.count)
      XCTAssertEqual(bytePointer.pointee, 0)
      XCTAssertEqual(bytePointer.successor().pointee, 1)
      XCTAssertEqual(bytePointer.successor().successor().pointee, UInt8.max - 1)
      XCTAssertEqual(bytePointer.advanced(by: 3).pointee, UInt8.max)
    }
  }
}
