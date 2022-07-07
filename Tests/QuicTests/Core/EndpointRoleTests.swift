//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

import XCTest
@testable import Quic

final class EndpointRoleTests: XCTestCase {
  func testDefaultInit() throws {
    XCTAssertEqual(EndpointRole(rawValue: 0), .client)
    XCTAssertEqual(EndpointRole(rawValue: 1), .server)

    XCTAssertNil(EndpointRole(rawValue: 2))
    XCTAssertNil(EndpointRole(rawValue: UInt8.max))
  }

  func testTruncatingInit() throws {
    XCTAssertEqual(EndpointRole(truncating: 0), .client)
    XCTAssertEqual(EndpointRole(truncating: 1), .server)

    XCTAssertEqual(EndpointRole(truncating: 2), .client)
    XCTAssertEqual(EndpointRole(truncating: UInt8.max), .server)
  }
}
