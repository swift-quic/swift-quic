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

final class HandshakePacketTests: XCTestCase {

    func testHandshakePacketDecryption() throws {
        let originalDCID = "a5cf37231d2b91d354b55dc2da5c5d33942b"
        let handshakeSecretClient = try Array(hexString: "38ce8cc4427519fc0581a052ed472a9a4f0970860b24838fe865ec4d79936329")
        let handshakeSecretServer = try Array(hexString: "6e0c985caa1cf3b8c0c428f8b5f7ab6d45155f68fd0aff4be5a50fda542d2618")
        // This is an invalid packet that we sent to a server while acting as a client...
        var handshakePacketBytes = try ByteBuffer(hexString: "e400000001040cb4ffc70579f5d72dfc37b834399c38a7acfb8982aa23d0e141f994e1441000c2e279a2ffffa710bd0e1c85802c9325505eb19de95c16bb76fd6b88d6100bcb7c4a8c")
        print(handshakePacketBytes.readableBytes)
        VarInt(integerLiteral: 73).withUnsafeBytes { print(Array($0).hexString) }

        // Create the servers handshake opener, in order to decrypt the client handshake message.
        var packetProtector = PacketProtector(epoch: .Handshake, version: .version1)
        try packetProtector.installKeySet(suite: .ChaChaPoly_SHA256, secret: handshakeSecretClient, for: .client, ourPerspective: .server)

        // Attempt to decrypt it
        let result = handshakePacketBytes.readEncryptedQuicHandshakePacket(using: packetProtector)
        print(result)
    }
}
