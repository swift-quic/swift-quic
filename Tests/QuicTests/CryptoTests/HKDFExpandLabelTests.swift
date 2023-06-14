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

import Crypto
import XCTest
@testable import Quic

final class HKDFExpandLabelTests: XCTestCase {

    /// A.1 - Keys - https://www.rfc-editor.org/rfc/rfc9001.pdf
    func testLabelGeneration() throws {
        // Client Initial
        let expectedClientIn = try Array(hexString: "0x00200f746c73313320636c69656e7420696e00")
        let clientIn = try HKDF<SHA256>.generateLabel(length: 32, label: "client in", hash: [])
        XCTAssertEqual(clientIn, expectedClientIn)

        // Server Initial
        let expectedServerIn = try Array(hexString: "0x00200f746c7331332073657276657220696e00")
        let serverIn = try HKDF<SHA256>.generateLabel(length: 32, label: "server in", hash: [])
        XCTAssertEqual(serverIn, expectedServerIn)

        // Quic Key
        let expectedQuicKey = try Array(hexString: "0x00100e746c7331332071756963206b657900")
        let quicKey = try HKDF<SHA256>.generateLabel(length: 16, label: "quic key", hash: [])
        XCTAssertEqual(quicKey, expectedQuicKey)

        // Quic IV
        let expectedQuicIV = try Array(hexString: "0x000c0d746c733133207175696320697600")
        let quicIV = try HKDF<SHA256>.generateLabel(length: 12, label: "quic iv", hash: [])
        XCTAssertEqual(quicIV, expectedQuicIV)

        // Quic HP
        let expectedQuicHP = try Array(hexString: "0x00100d746c733133207175696320687000")
        let quicHP = try HKDF<SHA256>.generateLabel(length: 16, label: "quic hp", hash: [])
        XCTAssertEqual(quicHP, expectedQuicHP)
    }

    /// A.1 - Keys - https://www.rfc-editor.org/rfc/rfc9001.pdf
    func testAppendix_1_Keys_From_Pre_Generated_Labels() throws {
        let destinationClientID = try Array(hexString: "0x8394c8f03e515708")

        let clientIn = try Array(hexString: "0x00200f746c73313320636c69656e7420696e00")
        let serverIn = try Array(hexString: "0x00200f746c7331332073657276657220696e00")
        let quicKey = try Array(hexString: "0x00100e746c7331332071756963206b657900")
        let quicIV = try Array(hexString: "0x000c0d746c733133207175696320697600")
        let quicHP = try Array(hexString: "0x00100d746c733133207175696320687000")

        // Initial Shared Secret
        let expectedInitialSecret = try Array(hexString: "0x7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44")
        let initialSecret = HKDF<SHA256>.extract(inputKeyMaterial: SymmetricKey(data: destinationClientID), salt: Version.version1.salt)
        XCTAssertEqual(initialSecret.withUnsafeBytes { Array($0) }, expectedInitialSecret)

        // Client Initial Secret
        let expectedClientInitialSecret = try Array(hexString: "0xc00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
        let clientInitialSecret = HKDF<SHA256>.expand(pseudoRandomKey: initialSecret, info: clientIn, outputByteCount: 32)
        XCTAssertEqual(clientInitialSecret.withUnsafeBytes { Array($0) }, expectedClientInitialSecret)

        // Client Key
        let expectedClientKey = try Array(hexString: "0x1f369613dd76d5467730efcbe3b1a22d")
        let clientKey = HKDF<SHA256>.expand(pseudoRandomKey: clientInitialSecret, info: quicKey, outputByteCount: 16)
        XCTAssertEqual(clientKey.withUnsafeBytes { Array($0) }, expectedClientKey)

        // Client IV
        let expectedClientIV = try Array(hexString: "0xfa044b2f42a3fd3b46fb255c")
        let clientIV = HKDF<SHA256>.expand(pseudoRandomKey: clientInitialSecret, info: quicIV, outputByteCount: 12)
        XCTAssertEqual(clientIV.withUnsafeBytes { Array($0) }, expectedClientIV)

        // Client HP
        let expectedClientHP = try Array(hexString: "0x9f50449e04a0e810283a1e9933adedd2")
        let clientHP = HKDF<SHA256>.expand(pseudoRandomKey: clientInitialSecret, info: quicHP, outputByteCount: 16)
        XCTAssertEqual(clientHP.withUnsafeBytes { Array($0) }, expectedClientHP)

        // Server Initial Secret
        let expectedServerInitialSecret = try Array(hexString: "0x3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b")
        let serverInitialSecret = HKDF<SHA256>.expand(pseudoRandomKey: initialSecret, info: serverIn, outputByteCount: 32)
        XCTAssertEqual(serverInitialSecret.withUnsafeBytes { Array($0) }, expectedServerInitialSecret)

        // Server Key
        let expectedServerKey = try Array(hexString: "0xcf3a5331653c364c88f0f379b6067e37")
        let serverKey = HKDF<SHA256>.expand(pseudoRandomKey: serverInitialSecret, info: quicKey, outputByteCount: 16)
        XCTAssertEqual(serverKey.withUnsafeBytes { Array($0) }, expectedServerKey)

        // Server IV
        let expectedServerIV = try Array(hexString: "0x0ac1493ca1905853b0bba03e")
        let serverIV = HKDF<SHA256>.expand(pseudoRandomKey: serverInitialSecret, info: quicIV, outputByteCount: 12)
        XCTAssertEqual(serverIV.withUnsafeBytes { Array($0) }, expectedServerIV)

        // Server HP
        let expectedServerHP = try Array(hexString: "0xc206b8d9b9f0f37644430b490eeaa314")
        let serverHP = HKDF<SHA256>.expand(pseudoRandomKey: serverInitialSecret, info: quicHP, outputByteCount: 16)
        XCTAssertEqual(serverHP.withUnsafeBytes { Array($0) }, expectedServerHP)
    }

    /// A.1 - Keys - https://www.rfc-editor.org/rfc/rfc9001.pdf
    func testAppendix_1_Keys_From_Raw_Labels() throws {
        let destinationClientID = try Array(hexString: "0x8394c8f03e515708")

        // Initial Shared Secret
        let expectedInitialSecret = try Array(hexString: "0x7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44")
        let initialSecret = HKDF<SHA256>.extract(inputKeyMaterial: SymmetricKey(data: destinationClientID), salt: Version.version1.salt)
        XCTAssertEqual(initialSecret.withUnsafeBytes { Array($0) }, expectedInitialSecret)

        // Client Initial Secret
        let expectedClientInitialSecret = try Array(hexString: "0xc00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
        let clientInitialSecret = try HKDF<SHA256>.expandLabel(pseudoRandomKey: initialSecret, label: "client in", outputByteCount: 32)
        XCTAssertEqual(clientInitialSecret.withUnsafeBytes { Array($0) }, expectedClientInitialSecret)

        // Client Key
        let expectedClientKey = try Array(hexString: "0x1f369613dd76d5467730efcbe3b1a22d")
        let clientKey = try HKDF<SHA256>.expandLabel(pseudoRandomKey: clientInitialSecret, label: "quic key", outputByteCount: 16)
        XCTAssertEqual(clientKey.withUnsafeBytes { Array($0) }, expectedClientKey)

        // Client IV
        let expectedClientIV = try Array(hexString: "0xfa044b2f42a3fd3b46fb255c")
        let clientIV = try HKDF<SHA256>.expandLabel(pseudoRandomKey: clientInitialSecret, label: "quic iv", outputByteCount: 12)
        XCTAssertEqual(clientIV.withUnsafeBytes { Array($0) }, expectedClientIV)

        // Client HP
        let expectedClientHP = try Array(hexString: "0x9f50449e04a0e810283a1e9933adedd2")
        let clientHP = try HKDF<SHA256>.expandLabel(pseudoRandomKey: clientInitialSecret, label: "quic hp", outputByteCount: 16)
        XCTAssertEqual(clientHP.withUnsafeBytes { Array($0) }, expectedClientHP)

        // Server Initial Secret
        let expectedServerInitialSecret = try Array(hexString: "0x3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b")
        let serverInitialSecret = try HKDF<SHA256>.expandLabel(pseudoRandomKey: initialSecret, label: "server in", outputByteCount: 32)
        XCTAssertEqual(serverInitialSecret.withUnsafeBytes { Array($0) }, expectedServerInitialSecret)

        // Server Key
        let expectedServerKey = try Array(hexString: "0xcf3a5331653c364c88f0f379b6067e37")
        let serverKey = try HKDF<SHA256>.expandLabel(pseudoRandomKey: serverInitialSecret, label: "quic key", outputByteCount: 16)
        XCTAssertEqual(serverKey.withUnsafeBytes { Array($0) }, expectedServerKey)

        // Server IV
        let expectedServerIV = try Array(hexString: "0x0ac1493ca1905853b0bba03e")
        let serverIV = try HKDF<SHA256>.expandLabel(pseudoRandomKey: serverInitialSecret, label: "quic iv", outputByteCount: 12)
        XCTAssertEqual(serverIV.withUnsafeBytes { Array($0) }, expectedServerIV)

        // Server HP
        let expectedServerHP = try Array(hexString: "0xc206b8d9b9f0f37644430b490eeaa314")
        let serverHP = try HKDF<SHA256>.expandLabel(pseudoRandomKey: serverInitialSecret, label: "quic hp", outputByteCount: 16)
        XCTAssertEqual(serverHP.withUnsafeBytes { Array($0) }, expectedServerHP)
    }

    /// A.5 - ChaCha20-Poly1305 Short Header Packet - https://www.rfc-editor.org/rfc/rfc9001.pdf
    func testAppendix_5_Keys_From_Raw_Labels() throws {
        let secret = try Array(hexString: "0x9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b")

        // Key
        let expectedKey = try Array(hexString: "0xc6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8")
        let key = try HKDF<SHA256>.expandLabel(pseudoRandomKey: secret, label: "quic key", outputByteCount: 32)
        XCTAssertEqual(key.withUnsafeBytes { Array($0) }, expectedKey)

        // IV
        let expectedIV = try Array(hexString: "0xe0459b3474bdd0e44a41c144")
        let iv = try HKDF<SHA256>.expandLabel(pseudoRandomKey: secret, label: "quic iv", outputByteCount: 12)
        XCTAssertEqual(iv.withUnsafeBytes { Array($0) }, expectedIV)

        // HP
        let expectedHP = try Array(hexString: "0x25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4")
        let hp = try HKDF<SHA256>.expandLabel(pseudoRandomKey: secret, label: "quic hp", outputByteCount: 32)
        XCTAssertEqual(hp.withUnsafeBytes { Array($0) }, expectedHP)

        // KU
        let expectedKU = try Array(hexString: "0x1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9")
        let ku = try HKDF<SHA256>.expandLabel(pseudoRandomKey: secret, label: "quic ku", outputByteCount: 32)
        XCTAssertEqual(ku.withUnsafeBytes { Array($0) }, expectedKU)
    }
}
