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

final class PacketProtectorTests: XCTestCase {

    func testPacketProtectorInitialKeySets_Version2() throws {
        let version = Version.version2
        let dcid = ConnectionID(with: try Array(hexString: "0x18af10fdfa370dd3b3"))

        // Generate our PacketProtector (Key Sets)
        let clientPacketProtector = try version.newInitialAEAD(connectionID: dcid, perspective: .client)
        let serverPacketProtector = try version.newInitialAEAD(connectionID: dcid, perspective: .server)

        // Ensure all of our keys match
        XCTAssertEqual(clientPacketProtector.opener!.decrypter.iv, serverPacketProtector.sealer!.encryptor.iv)
        XCTAssertEqual(clientPacketProtector.opener!.decrypter.key, serverPacketProtector.sealer!.encryptor.key)
        XCTAssertEqual(clientPacketProtector.opener!.headerProtector.cipher.key, serverPacketProtector.sealer!.headerProtector.cipher.key)

        XCTAssertEqual(clientPacketProtector.sealer!.encryptor.iv, serverPacketProtector.opener!.decrypter.iv)
        XCTAssertEqual(clientPacketProtector.sealer!.encryptor.key, serverPacketProtector.opener!.decrypter.key)
        XCTAssertEqual(clientPacketProtector.sealer!.headerProtector.cipher.key, serverPacketProtector.opener!.headerProtector.cipher.key)
    }

    func testPacketProtectorInitialKeySets_Version1() throws {
        let version = Version.version1
        let dcid = ConnectionID(with: try Array(hexString: "0x18af10fdfa370dd3b3"))

        // Generate our PacketProtector (Key Sets)
        let clientPacketProtector = try version.newInitialAEAD(connectionID: dcid, perspective: .client)
        let serverPacketProtector = try version.newInitialAEAD(connectionID: dcid, perspective: .server)

        // Ensure all of our keys match
        XCTAssertEqual(clientPacketProtector.opener!.decrypter.iv, serverPacketProtector.sealer!.encryptor.iv)
        XCTAssertEqual(clientPacketProtector.opener!.decrypter.key, serverPacketProtector.sealer!.encryptor.key)
        XCTAssertEqual(clientPacketProtector.opener!.headerProtector.cipher.key, serverPacketProtector.sealer!.headerProtector.cipher.key)

        XCTAssertEqual(clientPacketProtector.sealer!.encryptor.iv, serverPacketProtector.opener!.decrypter.iv)
        XCTAssertEqual(clientPacketProtector.sealer!.encryptor.key, serverPacketProtector.opener!.decrypter.key)
        XCTAssertEqual(clientPacketProtector.sealer!.headerProtector.cipher.key, serverPacketProtector.opener!.headerProtector.cipher.key)
    }

    func testPacketProtectorInitialKeySets_Draft29() throws {
        let version = Version.versionDraft29
        let dcid = ConnectionID(with: try Array(hexString: "0x18af10fdfa370dd3b3"))

        // Generate our PacketProtector (Key Sets)
        let clientPacketProtector = try version.newInitialAEAD(connectionID: dcid, perspective: .client)
        let serverPacketProtector = try version.newInitialAEAD(connectionID: dcid, perspective: .server)

        // Ensure all of our keys match
        XCTAssertEqual(clientPacketProtector.opener!.decrypter.iv, serverPacketProtector.sealer!.encryptor.iv)
        XCTAssertEqual(clientPacketProtector.opener!.decrypter.key, serverPacketProtector.sealer!.encryptor.key)
        XCTAssertEqual(clientPacketProtector.opener!.headerProtector.cipher.key, serverPacketProtector.sealer!.headerProtector.cipher.key)

        XCTAssertEqual(clientPacketProtector.sealer!.encryptor.iv, serverPacketProtector.opener!.decrypter.iv)
        XCTAssertEqual(clientPacketProtector.sealer!.encryptor.key, serverPacketProtector.opener!.decrypter.key)
        XCTAssertEqual(clientPacketProtector.sealer!.headerProtector.cipher.key, serverPacketProtector.opener!.headerProtector.cipher.key)
    }

    func testPacketProtectorSecretBasedKeySets_Version2() throws {
        let version = Version.version2
        let clientSecret = try Array(hexString: "0x9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b")
        let serverSecret = try Array(hexString: "0x93a1d30d4cc3fb380cc52183a01c5281eb081aa1c9c7d48e1861ce1c62f024b6")

        // Generate our PacketProtector (Key Sets)
        let clientPacketProtector = try version.newAEAD(clientSecret: clientSecret, serverSecret: serverSecret, perspective: .client, suite: .AESGCM128_SHA256, epoch: .Application)
        let serverPacketProtector = try version.newAEAD(clientSecret: clientSecret, serverSecret: serverSecret, perspective: .server, suite: .AESGCM128_SHA256, epoch: .Application)

        // Ensure all of our keys match
        XCTAssertEqual(clientPacketProtector.opener!.decrypter.iv, serverPacketProtector.sealer!.encryptor.iv)
        XCTAssertEqual(clientPacketProtector.opener!.decrypter.key, serverPacketProtector.sealer!.encryptor.key)
        XCTAssertEqual(clientPacketProtector.opener!.headerProtector.cipher.key, serverPacketProtector.sealer!.headerProtector.cipher.key)

        XCTAssertEqual(clientPacketProtector.sealer!.encryptor.iv, serverPacketProtector.opener!.decrypter.iv)
        XCTAssertEqual(clientPacketProtector.sealer!.encryptor.key, serverPacketProtector.opener!.decrypter.key)
        XCTAssertEqual(clientPacketProtector.sealer!.headerProtector.cipher.key, serverPacketProtector.opener!.headerProtector.cipher.key)
    }

    func testPacketProtectorSecretBasedKeySets_Version1() throws {
        let version = Version.version1
        let clientSecret = try Array(hexString: "0x9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b")
        let serverSecret = try Array(hexString: "0x93a1d30d4cc3fb380cc52183a01c5281eb081aa1c9c7d48e1861ce1c62f024b6")

        // Generate our PacketProtector (Key Sets)
        let clientPacketProtector = try version.newAEAD(clientSecret: clientSecret, serverSecret: serverSecret, perspective: .client, suite: .AESGCM128_SHA256, epoch: .Application)
        let serverPacketProtector = try version.newAEAD(clientSecret: clientSecret, serverSecret: serverSecret, perspective: .server, suite: .AESGCM128_SHA256, epoch: .Application)

        // Ensure all of our keys match
        XCTAssertEqual(clientPacketProtector.opener!.decrypter.iv, serverPacketProtector.sealer!.encryptor.iv)
        XCTAssertEqual(clientPacketProtector.opener!.decrypter.key, serverPacketProtector.sealer!.encryptor.key)
        XCTAssertEqual(clientPacketProtector.opener!.headerProtector.cipher.key, serverPacketProtector.sealer!.headerProtector.cipher.key)

        XCTAssertEqual(clientPacketProtector.sealer!.encryptor.iv, serverPacketProtector.opener!.decrypter.iv)
        XCTAssertEqual(clientPacketProtector.sealer!.encryptor.key, serverPacketProtector.opener!.decrypter.key)
        XCTAssertEqual(clientPacketProtector.sealer!.headerProtector.cipher.key, serverPacketProtector.opener!.headerProtector.cipher.key)
    }

    func testPacketProtectorSecretBasedKeySets_Draft29() throws {
        let version = Version.versionDraft29
        let clientSecret = try Array(hexString: "0x9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b")
        let serverSecret = try Array(hexString: "0x93a1d30d4cc3fb380cc52183a01c5281eb081aa1c9c7d48e1861ce1c62f024b6")

        // Generate our PacketProtector (Key Sets)
        let clientPacketProtector = try version.newAEAD(clientSecret: clientSecret, serverSecret: serverSecret, perspective: .client, suite: .AESGCM128_SHA256, epoch: .Application)
        let serverPacketProtector = try version.newAEAD(clientSecret: clientSecret, serverSecret: serverSecret, perspective: .server, suite: .AESGCM128_SHA256, epoch: .Application)

        // Ensure all of our keys match
        XCTAssertEqual(clientPacketProtector.opener!.decrypter.iv, serverPacketProtector.sealer!.encryptor.iv)
        XCTAssertEqual(clientPacketProtector.opener!.decrypter.key, serverPacketProtector.sealer!.encryptor.key)
        XCTAssertEqual(clientPacketProtector.opener!.headerProtector.cipher.key, serverPacketProtector.sealer!.headerProtector.cipher.key)

        XCTAssertEqual(clientPacketProtector.sealer!.encryptor.iv, serverPacketProtector.opener!.decrypter.iv)
        XCTAssertEqual(clientPacketProtector.sealer!.encryptor.key, serverPacketProtector.opener!.decrypter.key)
        XCTAssertEqual(clientPacketProtector.sealer!.headerProtector.cipher.key, serverPacketProtector.opener!.headerProtector.cipher.key)
    }

    /// Initial KeySet Generation - All Versions
    func testPacketProtectorInitialKeySets() throws {
        let dcid = ConnectionID(with: try Array(hexString: "0x18af10fdfa370dd3b3"))

        for version in Quic.supportedVersions {
            // Generate our PacketProtector (Key Sets)
            let clientPacketProtector = try version.newInitialAEAD(connectionID: dcid, perspective: .client)
            let serverPacketProtector = try version.newInitialAEAD(connectionID: dcid, perspective: .server)

            // Ensure all of our keys match
            XCTAssertEqual(clientPacketProtector.opener!.decrypter.iv, serverPacketProtector.sealer!.encryptor.iv, "KeySet Generation Failed for Version: \(version) - Cipher IV")
            XCTAssertEqual(clientPacketProtector.opener!.decrypter.key, serverPacketProtector.sealer!.encryptor.key, "KeySet Generation Failed for Version: \(version) - Cipher Key")
            XCTAssertEqual(clientPacketProtector.opener!.headerProtector.cipher.key, serverPacketProtector.sealer!.headerProtector.cipher.key, "KeySet Generation Failed for Version: \(version) - HP Key")

            XCTAssertEqual(clientPacketProtector.sealer!.encryptor.iv, serverPacketProtector.opener!.decrypter.iv, "KeySet Generation Failed for Version: \(version) - Cipher IV")
            XCTAssertEqual(clientPacketProtector.sealer!.encryptor.key, serverPacketProtector.opener!.decrypter.key, "KeySet Generation Failed for Version: \(version) - Cipher Key")
            XCTAssertEqual(clientPacketProtector.sealer!.headerProtector.cipher.key, serverPacketProtector.opener!.headerProtector.cipher.key, "KeySet Generation Failed for Version: \(version) - HP Key")
        }
    }

    /// Secret Based KeySet Generation - All Versions + All Ciphers
    func testPacketProtectorSecretBasedKeySets() throws {
        let clientSecret = try Array(hexString: "0x9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b")
        let serverSecret = try Array(hexString: "0x93a1d30d4cc3fb380cc52183a01c5281eb081aa1c9c7d48e1861ce1c62f024b6")

        for version in Quic.supportedVersions {
            for cipher in CipherSuite.allCases {
                // Generate our PacketProtector (Key Sets)
                let clientPacketProtector = try version.newAEAD(clientSecret: clientSecret, serverSecret: serverSecret, perspective: .client, suite: cipher, epoch: .Application)
                let serverPacketProtector = try version.newAEAD(clientSecret: clientSecret, serverSecret: serverSecret, perspective: .server, suite: cipher, epoch: .Application)

                // Ensure all of our keys match
                XCTAssertEqual(clientPacketProtector.opener!.decrypter.iv, serverPacketProtector.sealer!.encryptor.iv, "KeySet Generation Failed for Version: \(version) & CipherSuite: \(cipher) - Cipher IV")
                XCTAssertEqual(clientPacketProtector.opener!.decrypter.key, serverPacketProtector.sealer!.encryptor.key, "KeySet Generation Failed for Version: \(version) & CipherSuite: \(cipher) - Cipher Key")
                XCTAssertEqual(clientPacketProtector.opener!.headerProtector.cipher.key, serverPacketProtector.sealer!.headerProtector.cipher.key, "KeySet Generation Failed for Version: \(version) & CipherSuite: \(cipher) - HP Key")

                XCTAssertEqual(clientPacketProtector.sealer!.encryptor.iv, serverPacketProtector.opener!.decrypter.iv, "KeySet Generation Failed for Version: \(version) & CipherSuite: \(cipher) - Cipher IV")
                XCTAssertEqual(clientPacketProtector.sealer!.encryptor.key, serverPacketProtector.opener!.decrypter.key, "KeySet Generation Failed for Version: \(version) & CipherSuite: \(cipher) - Cipher Key")
                XCTAssertEqual(clientPacketProtector.sealer!.headerProtector.cipher.key, serverPacketProtector.opener!.headerProtector.cipher.key, "KeySet Generation Failed for Version: \(version) & CipherSuite: \(cipher) - HP Key")
            }
        }
    }
}
