//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

import XCTest
@testable import Quic

import ByteArrayCodable

final class VarIntTests: XCTestCase {
  func testMax() throws {
    XCTAssertNotNil(VarInt(rawValue: VarInt.max))
    XCTAssertEqual(VarInt(rawValue: VarInt.max)?.rawValue, VarInt.max)
  }

  func testUpperBound() throws {
    XCTAssertEqual(VarInt.upperBound, VarInt.max + 1)
    XCTAssertNil(VarInt(rawValue: VarInt.upperBound))
    XCTAssertNil(VarInt(rawValue: VarInt.upperBound + 1))
    XCTAssertNil(VarInt(rawValue: UInt64.max))
  }

  func testEncoding() throws {
    let encoder = ByteArrayEncoder()
    var bytes: [UInt8]

    let zero = VarInt(rawValue: 0)!
    bytes = try encoder.encode(zero)
    XCTAssertEqual(bytes, [0])

    let maxUInt8 = VarInt(rawValue: 0x3f)!
    bytes = try encoder.encode(maxUInt8)
    XCTAssertEqual(bytes, [0x3f])

    let minUInt16 = VarInt(rawValue: 0x40)!
    bytes = try encoder.encode(minUInt16)
    XCTAssertEqual(bytes, [0x40, 0x40])

    let maxUInt16 = VarInt(rawValue: 0x3fff)!
    bytes = try encoder.encode(maxUInt16)
    XCTAssertEqual(bytes, [0x7f, 0xff])

    let minUInt32 = VarInt(rawValue: 0x4000)!
    bytes = try encoder.encode(minUInt32)
    XCTAssertEqual(bytes, [0x80, 0, 0x40, 0])

    let maxUInt32 = VarInt(rawValue: 0x3fff_ffff)!
    bytes = try encoder.encode(maxUInt32)
    XCTAssertEqual(bytes, [0xbf, 0xff, 0xff, 0xff])

    let minUInt64 = VarInt(rawValue: 0x4000_0000)!
    bytes = try encoder.encode(minUInt64)
    XCTAssertEqual(bytes, [0xc0, 0, 0, 0, 0x40, 0, 0, 0])

    let maxUInt64 = VarInt(rawValue: VarInt.max)!
    bytes = try encoder.encode(maxUInt64)
    XCTAssertEqual(bytes, [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
  }

  func testDecoding() throws {
    let decoder = ByteArrayDecoder(data: [
      0,
      0x3f,
      0x40, 0x40,
      0x7f, 0xff,
      0x80, 0, 0x40, 0,
      0xbf, 0xff, 0xff, 0xff,
      0xc0, 0, 0, 0, 0x40, 0, 0 , 0,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    ])

    let zero = try VarInt(from: decoder)
    XCTAssertEqual(zero, VarInt(rawValue: 0)!)

    let maxUInt8 = try VarInt(from: decoder)
    XCTAssertEqual(maxUInt8, VarInt(rawValue: 0x3f)!)

    let minUInt16 = try VarInt(from: decoder)
    XCTAssertEqual(minUInt16, VarInt(rawValue: 0x40)!)

    let maxUInt16 = try VarInt(from: decoder)
    XCTAssertEqual(maxUInt16, VarInt(rawValue: 0x3fff)!)

    let minUInt32 = try VarInt(from: decoder)
    XCTAssertEqual(minUInt32, VarInt(rawValue: 0x4000)!)

    let maxUInt32 = try VarInt(from: decoder)
    XCTAssertEqual(maxUInt32, VarInt(rawValue: 0x3fff_ffff)!)

    let minUInt64 = try VarInt(from: decoder)
    XCTAssertEqual(minUInt64, VarInt(rawValue: 0x4000_0000)!)

    let maxUInt64 = try VarInt(from: decoder)
    XCTAssertEqual(maxUInt64, VarInt(rawValue: VarInt.max)!)
  }
}
