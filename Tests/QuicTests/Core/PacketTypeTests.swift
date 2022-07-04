//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

import XCTest
@testable import Quic

final class PacketTypeTests: XCTestCase {
  func testAllBytes() throws {
    let allBytes: ClosedRange<UInt8> = UInt8.min...UInt8.max
    XCTAssertTrue(allBytes.contains(0))
    XCTAssertTrue(allBytes.contains(UInt8.max))
  }
}
