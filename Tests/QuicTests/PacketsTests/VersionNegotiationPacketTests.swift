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

import NIOCore
import XCTest
@testable import Quic

final class VersionNegotiationPacketTests: XCTestCase {
    func testVersionNegotiationPacket() throws {
        let destinationID: ConnectionID = []
        let sourceID: ConnectionID = [0]
        let packet = VersionNegotiationPacket(destinationID: destinationID, sourceID: sourceID)

        XCTAssertEqual(packet.header.firstByte, 0b1100_0000)
        XCTAssertEqual(packet.header.version, .negotiation)
        XCTAssertEqual(packet.serializedPayload.count % MemoryLayout<Version>.size, 0)

        XCTAssertEqual(packet.header.destinationIDLength, UInt8(destinationID.length))
        XCTAssertEqual(packet.header.destinationID, destinationID)
        XCTAssertEqual(packet.header.sourceIDLength, UInt8(sourceID.length))
        XCTAssertEqual(packet.header.sourceID, sourceID)

        let payload = supportedVersions.flatMap { version in
            version.withUnsafeBytes { Array($0) }
        }
        XCTAssertEqual(packet.serializedPayload, payload)

        XCTAssertEqual(packet.versions, supportedVersions)
    }

    func testVersionNegotiationPacketDecodingManual() throws {
        // An example of a VersionNegotationPacket emitted from QUIC Go
        var buffer = try ByteBuffer(hexString: "9d00000000000c65a3d45a9b2a7aca5cf1dcfc000000016b3343cfbafa0aeaff00001d")

        // The first byte only tells us that it's a Long Form Header (the last 7 bits are unused / artbitrary)
        guard let firstByte = buffer.readBytes(length: 1)?.first else { XCTFail("Failed to read the first byte"); return }
        let form = HeaderForm(rawValue: firstByte & HeaderForm.mask)
        XCTAssertEqual(form, .long)

        // The fact that the Version is set to 0 is the indicating factor that this is a Version negotiation packet
        guard let version = buffer.readVersion() else { XCTFail("Failed to read Version"); return }
        XCTAssertEqual(version.rawValue, 0)
        XCTAssertEqual(version.bytes, Array<UInt8>(arrayLiteral: 0x00, 0x00, 0x00, 0x00))

        guard let dcid = buffer.readConnectionID() else { XCTFail("Failed to read DCID"); return }
        print(dcid)
        guard let scid = buffer.readConnectionID() else { XCTFail("Failed to read SCID"); return }
        print(scid)

        var supportedVersions: [Version] = []
        while buffer.readableBytes > 0, let v = buffer.readVersion() {
            supportedVersions.append(v)
        }

        XCTAssertEqual(buffer.readableBytes, 0)

        print(supportedVersions)
        supportedVersions.forEach {
            print($0.bytes.hexString)
        }
        XCTAssertEqual(supportedVersions, [
            .version1,
            .version2,
            Version(integerLiteral: 3136948970),
            .versionDraft29
        ])
    }

    func testVersionNegotiationPacketDecoding() throws {
        // An example of a VersionNegotationPacket emitted from QUIC Go
        var buffer = try ByteBuffer(hexString: "9d00000000000c65a3d45a9b2a7aca5cf1dcfc000000016b3343cfbafa0aeaff00001d")

        guard let vn = buffer.readVersionNegotiationPacket() else { return XCTFail("Failed to read Version Negotiation Packet from buffer") }

        XCTAssertEqual(buffer.readableBytes, 0)
        XCTAssertEqual(vn.header.destinationID, ConnectionID())
        XCTAssertEqual(vn.header.sourceID, ConnectionID(arrayLiteral: 101, 163, 212, 90, 155, 42, 122, 202, 92, 241, 220, 252))
        XCTAssertEqual(vn.versions, [
            .version1,
            .version2,
            Version(integerLiteral: 3136948970),
            .versionDraft29
        ])
    }
}
