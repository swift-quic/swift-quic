//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

import XCTest
@testable import Quic

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

  func testLiteral() throws {
    let zero: VarInt = 0
    XCTAssertEqual(zero, 0)

    let max: VarInt = 0x3fff_ffff_ffff_ffff
    XCTAssertEqual(max, VarInt.max)
  }

  func testInitWithBytes() throws {
    let data: [UInt8] = [
      0,
      0x3f,
      0x40, 0x40,
      0x7f, 0xff,
      0x80, 0, 0x40, 0,
      0xbf, 0xff, 0xff, 0xff,
      0xc0, 0, 0, 0, 0x40, 0, 0 , 0,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    ]

    let minUInt8 = VarInt(rawValue: 0)
    let maxUInt8 = VarInt(rawValue: 0x3f)
    let minUInt16 = VarInt(rawValue: 0x40)
    let maxUInt16 = VarInt(rawValue: 0x3fff)
    let minUInt32 = VarInt(rawValue: 0x4000)
    let maxUInt32 = VarInt(rawValue: 0x3fff_ffff)
    let minUInt64 = VarInt(rawValue: 0x4000_0000)
    let maxUInt64 = VarInt(rawValue: VarInt.maxRawValue)

    XCTAssertEqual(VarInt(with: data), minUInt8)
    XCTAssertEqual(VarInt(with: data.dropFirst()), maxUInt8)
    XCTAssertEqual(VarInt(with: data.dropFirst(2)), minUInt16)
    XCTAssertEqual(VarInt(with: data.dropFirst(4)), maxUInt16)
    XCTAssertEqual(VarInt(with: data.dropFirst(6)), minUInt32)
    XCTAssertEqual(VarInt(with: data.dropFirst(10)), maxUInt32)
    XCTAssertEqual(VarInt(with: data.dropFirst(14)), minUInt64)
    XCTAssertEqual(VarInt(with: data.dropFirst(22)), maxUInt64)

    XCTAssertEqual(VarInt(with: []), VarInt(rawValue: 0))
  }

  func testWithUnsafeBytes() throws {
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
  
  func testAppendix1VariableLengthIntegerDecoding_Read() throws {
    let val1 = try Array(hexString: "0xc2197c5eff14e88c")
    XCTAssertEqual(val1.readQuicVarInt(), 151_288_809_941_952_652)
    
    let val2 = try Array(hexString: "0x9d7f3e7d")
    XCTAssertEqual(val2.readQuicVarInt(), 494_878_333)
    
    let val3 = try Array(hexString: "0x7bbd")
    XCTAssertEqual(val3.readQuicVarInt(), 15_293)
    
    let val4 = try Array(hexString: "0x25")
    XCTAssertEqual(val4.readQuicVarInt(), 37)
    
    let val5 = try Array(hexString: "0x4025")
    XCTAssertEqual(val5.readQuicVarInt(), 37)
  }
  
  func testAppendix1VariableLengthIntegerDecoding_Write() throws {
    let val1 = writeQuicVarInt(151_288_809_941_952_652)
    XCTAssertEqual(val1, try Array(hexString: "0xc2197c5eff14e88c"))
    
    let val2 = writeQuicVarInt(494_878_333)
    XCTAssertEqual(val2, try Array(hexString: "0x9d7f3e7d"))
    
    let val3 = writeQuicVarInt(15_293)
    XCTAssertEqual(val3, try Array(hexString: "0x7bbd"))
    
    let val4 = writeQuicVarInt(37)
    XCTAssertEqual(val4, try Array(hexString: "0x25"))
    
    let val5 = writeQuicVarInt(37, minBytes: 2)
    XCTAssertEqual(val5, try Array(hexString: "0x4025"))
  }
}
