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
}
