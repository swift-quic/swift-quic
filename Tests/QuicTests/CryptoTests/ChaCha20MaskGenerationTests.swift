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

import _CryptoExtras
import Crypto
import XCTest
@testable import Quic

final class ChaCha20MaskGenerationTests: XCTestCase {

    /// Test Vector - https://datatracker.ietf.org/doc/html/rfc9001#name-chacha20-poly1305-short-hea
    func testChaCha20ExplicitCounterV1() throws {
        let hpKey = try Array(hexString: "0x25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4")
        /// Sample = 0x5e5cd55c41f69080575d7999c25a5bfb
        let counter = try Array(hexString: "0x5e5cd55c")
        let iv = try Array(hexString: "0x41f69080575d7999c25a5bfb")

        do {
            let mask = try Crypto.Insecure.ChaCha20CTR.encrypt(Array<UInt8>(repeating: 0, count: 5), using: SymmetricKey(data: hpKey), counter: .init(data: counter), nonce: .init(data: iv))

            XCTAssertEqual(Array(mask), try Array(hexString: "0xaefefe7d03"))
        } catch {
            XCTFail("\(error)")
        }
    }

    /// Test Vector - https://www.ietf.org/archive/id/draft-ietf-quic-v2-10.html#name-chacha20-poly1305-short-head
    func testChaCha20ExplicitCounterV2() throws {
        let hpKey = try Array(hexString: "0xd659760d2ba434a226fd37b35c69e2da8211d10c4f12538787d65645d5d1b8e2")
        /// Sample = 0xe7b6b932bc27d786f4bc2bb20f2162ba
        let counter = try Array(hexString: "0xe7b6b932")
        let iv = try Array(hexString: "0xbc27d786f4bc2bb20f2162ba")

        do {
            let mask = try Crypto.Insecure.ChaCha20CTR.encrypt(Array<UInt8>(repeating: 0, count: 5), using: SymmetricKey(data: hpKey), counter: .init(data: counter), nonce: .init(data: iv))

            XCTAssertEqual(Array(mask), try Array(hexString: "0x97580e32bf"))
        } catch {
            XCTFail("\(error)")
        }
    }
}
