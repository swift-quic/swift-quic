//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

import XCTest
@testable import Quic

import ByteArrayCodable

final class VarIntTests: XCTestCase {
  func testMax() throws {
    XCTAssertEqual(VarInt.max.rawValue, (1 << 62) - 1)
    XCTAssertEqual(VarInt.maxRawValue, VarInt.max.rawValue)
  }

  func testUpperBound() throws {
    XCTAssertEqual(VarInt.upperBound, VarInt.maxRawValue + 1)
    XCTAssertEqual(VarInt(rawValue: VarInt.upperBound - 1), VarInt.max)

    XCTAssertNil(VarInt(rawValue: VarInt.upperBound))
    XCTAssertNil(VarInt(rawValue: UInt64.max))
  }

  func testBytes() throws {
    var bytes: [UInt8] = []
    bytes.append(contentsOf: VarInt(rawValue: 0)!.bytes)
    bytes.append(contentsOf: VarInt(rawValue: 0x3f)!.bytes)
    bytes.append(contentsOf: VarInt(rawValue: 0x40)!.bytes)
    bytes.append(contentsOf: VarInt(rawValue: 0x3fff)!.bytes)
    bytes.append(contentsOf: VarInt(rawValue: 0x4000)!.bytes)
    bytes.append(contentsOf: VarInt(rawValue: 0x3fff_ffff)!.bytes)
    bytes.append(contentsOf: VarInt(rawValue: 0x4000_0000)!.bytes)
    bytes.append(contentsOf: VarInt(rawValue: VarInt.maxRawValue)!.bytes)

    XCTAssertEqual(
      bytes,
      [
        0,
        0x3f,
        0x40, 0x40,
        0x7f, 0xff,
        0x80, 0, 0x40, 0,
        0xbf, 0xff, 0xff, 0xff,
        0xc0, 0, 0, 0, 0x40, 0, 0 , 0,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      ]
    )
  }

  func testInitWithBytes() throws {
    let minUInt8 = VarInt(rawValue: 0)
    let maxUInt8 = VarInt(rawValue: 0x3f)
    let minUInt16 = VarInt(rawValue: 0x40)
    let maxUInt16 = VarInt(rawValue: 0x3fff)
    let minUInt32 = VarInt(rawValue: 0x4000)
    let maxUInt32 = VarInt(rawValue: 0x3fff_ffff)
    let minUInt64 = VarInt(rawValue: 0x4000_0000)
    let maxUInt64 = VarInt(rawValue: VarInt.maxRawValue)

    XCTAssertEqual(VarInt(with: minUInt8!.bytes), minUInt8)
    XCTAssertEqual(VarInt(with: maxUInt8!.bytes), maxUInt8)
    XCTAssertEqual(VarInt(with: minUInt16!.bytes), minUInt16)
    XCTAssertEqual(VarInt(with: maxUInt16!.bytes), maxUInt16)
    XCTAssertEqual(VarInt(with: minUInt32!.bytes), minUInt32)
    XCTAssertEqual(VarInt(with: maxUInt32!.bytes), maxUInt32)
    XCTAssertEqual(VarInt(with: minUInt64!.bytes), minUInt64)
    XCTAssertEqual(VarInt(with: maxUInt64!.bytes), maxUInt64)

    XCTAssertEqual(VarInt(with: []), VarInt(rawValue: 0))
  }

  func testContiguousBytes() throws {
    let minUInt8 = VarInt(rawValue: 0)
    let maxUInt8 = VarInt(rawValue: 0x3f)
    let minUInt16 = VarInt(rawValue: 0x40)
    let maxUInt16 = VarInt(rawValue: 0x3fff)
    let minUInt32 = VarInt(rawValue: 0x4000)
    let maxUInt32 = VarInt(rawValue: 0x3fff_ffff)
    let minUInt64 = VarInt(rawValue: 0x4000_0000)
    let maxUInt64 = VarInt(rawValue: VarInt.maxRawValue)

    minUInt8?.withUnsafeBytes { pointer in
      XCTAssertEqual(VarInt(with: pointer), minUInt8)
    }

    maxUInt8?.withUnsafeBytes { pointer in
      XCTAssertEqual(VarInt(with: pointer), maxUInt8)
    }

    minUInt16?.withUnsafeBytes { pointer in
      XCTAssertEqual(VarInt(with: pointer), minUInt16)
    }

    maxUInt16?.withUnsafeBytes { pointer in
      XCTAssertEqual(VarInt(with: pointer), maxUInt16)
    }

    minUInt32?.withUnsafeBytes { pointer in
      XCTAssertEqual(VarInt(with: pointer), minUInt32)
    }

    maxUInt32?.withUnsafeBytes { pointer in
      XCTAssertEqual(VarInt(with: pointer), maxUInt32)
    }

    minUInt64?.withUnsafeBytes { pointer in
      XCTAssertEqual(VarInt(with: pointer), minUInt64)
    }

    maxUInt64?.withUnsafeBytes { pointer in
      XCTAssertEqual(VarInt(with: pointer), maxUInt64)
    }
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

    bytes = try encoder.encode(VarInt.max)
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
    XCTAssertEqual(maxUInt64, VarInt.max)

    XCTAssertThrowsError(try VarInt(from: decoder))
  }

  func testCodable() throws {
    var data: [UInt8] = []
    let minUInt8 = VarInt(rawValue: 0)
    let maxUInt8 = VarInt(rawValue: 0x3f)
    let minUInt16 = VarInt(rawValue: 0x40)
    let maxUInt16 = VarInt(rawValue: 0x3fff)
    let minUInt32 = VarInt(rawValue: 0x4000)
    let maxUInt32 = VarInt(rawValue: 0x3fff_ffff)
    let minUInt64 = VarInt(rawValue: 0x4000_0000)
    let maxUInt64 = VarInt(rawValue: VarInt.maxRawValue)

    let encoder = ByteArrayEncoder()
    data.append(contentsOf: try encoder.encode(minUInt8))
    data.append(contentsOf: try encoder.encode(maxUInt8))
    data.append(contentsOf: try encoder.encode(minUInt16))
    data.append(contentsOf: try encoder.encode(maxUInt16))
    data.append(contentsOf: try encoder.encode(minUInt32))
    data.append(contentsOf: try encoder.encode(maxUInt32))
    data.append(contentsOf: try encoder.encode(minUInt64))
    data.append(contentsOf: try encoder.encode(maxUInt64))

    let decoder = ByteArrayDecoder(data: data)
    XCTAssertEqual(try VarInt(from: decoder), minUInt8)
    XCTAssertEqual(try VarInt(from: decoder), maxUInt8)
    XCTAssertEqual(try VarInt(from: decoder), minUInt16)
    XCTAssertEqual(try VarInt(from: decoder), maxUInt16)
    XCTAssertEqual(try VarInt(from: decoder), minUInt32)
    XCTAssertEqual(try VarInt(from: decoder), maxUInt32)
    XCTAssertEqual(try VarInt(from: decoder), minUInt64)
    XCTAssertEqual(try VarInt(from: decoder), maxUInt64)
  }
}
