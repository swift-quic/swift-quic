//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

import XCTest
@testable import Quic

final class EndpointRoleTests: XCTestCase {
  func testInit() throws {
    XCTAssertEqual(EndpointRole(rawValue: 0), .client)
    XCTAssertEqual(EndpointRole(rawValue: 1), .server)

    XCTAssertNil(EndpointRole(rawValue: 2))
    XCTAssertNil(EndpointRole(rawValue: UInt8.max))
  }

  func testTruncating() throws {
    XCTAssertEqual(EndpointRole(truncatingIfNeeded: 0), .client)
    XCTAssertEqual(EndpointRole(truncatingIfNeeded: 1), .server)

    XCTAssertEqual(EndpointRole(truncatingIfNeeded: 2), .client)
    XCTAssertEqual(EndpointRole(truncatingIfNeeded: 3), .server)

    XCTAssertEqual(EndpointRole(truncatingIfNeeded: UInt8.max - 1), .client)
    XCTAssertEqual(EndpointRole(truncatingIfNeeded: UInt8.max), .server)
  }
}
