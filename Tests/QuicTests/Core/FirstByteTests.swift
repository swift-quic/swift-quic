//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

import XCTest
@testable import Quic

final class FirstByteTests: XCTestCase {
  func testFirstByte() throws {
    for byte in UInt8.min...UInt8.max {
      let firstByte = FirstByte(rawValue: byte)
      XCTAssertFalse(firstByte.contains(.long) && !firstByte.contains(.quic))

      XCTAssertFalse(firstByte.contains(.initial) && !firstByte.contains(.long))
      XCTAssertFalse(firstByte.contains(.zeroRTT) && !firstByte.contains(.long))
      XCTAssertFalse(firstByte.contains(.handshake) && !firstByte.contains(.long))
      XCTAssertFalse(firstByte.contains(.retry) && !firstByte.contains(.long))

      XCTAssertFalse(firstByte == .zeroRTT && firstByte == .handshake)
    }
  }
}
