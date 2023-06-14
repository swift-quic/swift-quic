//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftQUIC open source project
//
// Copyright (c) 2023 the SwiftQUIC project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftQUIC project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import XCTest
@testable import Quic

final class QuicTests: XCTestCase {
    func testVersion1() throws {
        XCTAssertEqual(Version(rawValue: 1), .version1)
        XCTAssertFalse(isNegotiation(version: .version1))
        XCTAssertFalse(isReserved(version: .version1))
    }

    func testCurrentVersion() throws {
        XCTAssertEqual(.version1, currentVersion)
        XCTAssertTrue(isKnown(version: currentVersion))
        XCTAssertTrue(isSupported(version: currentVersion))
    }

    func testKnownVersions() throws {
        XCTAssertTrue(isKnown(version: .version2))
        XCTAssertTrue(isKnown(version: .version1))
        XCTAssertTrue(isKnown(version: .versionDraft29))
    }

    func testSupportedVersions() throws {
        // Unsupported Versions
        XCTAssertFalse(isSupported(version: .version2))
        // Supported Versions
        XCTAssertTrue(isSupported(version: .version1))
        XCTAssertTrue(isSupported(version: .versionDraft29))
    }

    func testMinDatagramSize() throws {
        XCTAssertEqual(minDatagramSize, 1200)
    }

    func testMaxConnectionIDLength() throws {
        XCTAssertEqual(maxConnectionIDLength, 20)
    }

    /// https://datatracker.ietf.org/doc/html/rfc9000#section-a.2
    func testEncodePacketNumber() throws {
        let largestAcked = UInt64("abe8b3", radix: 16)!
        let packetNumberToSend = UInt64("ac5c02", radix: 16)!

        let outstandingPackets = packetNumberToSend - largestAcked
        XCTAssertEqual(outstandingPackets, 29_519)

        let pn = encodePacketNumber(fullPacketNumber: packetNumberToSend, largestAcked: largestAcked)
        print(pn.hexString)
        XCTAssertEqual(pn.count, 2)

        let packetNumberToSend2 = UInt64("ace8fe", radix: 16)!

        let outstandingPackets2 = packetNumberToSend2 - largestAcked
        XCTAssertEqual(outstandingPackets2, 65_611)

        let pn2 = encodePacketNumber(fullPacketNumber: packetNumberToSend2, largestAcked: largestAcked)
        print(pn2.hexString)
        XCTAssertEqual(pn2.count, 3)
    }

    /// https://datatracker.ietf.org/doc/html/rfc9000#section-a.3
    func testDecodePacketNumber() throws {
        let largestKnownPacketNumber = UInt64("a82f30ea", radix: 16)!
        let currentPacketNumber = UInt64("9b32", radix: 16)!

        let decoded = decodePacketNumber(largest: largestKnownPacketNumber, truncated: currentPacketNumber, nBits: 16)
        print(decoded)
        XCTAssertEqual(decoded, UInt64("a82f9b32", radix: 16))
    }
}
