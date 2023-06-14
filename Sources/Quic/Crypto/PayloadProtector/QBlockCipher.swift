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
import Foundation

protocol QCipher {
    static func encrypt<M, A>(message: M, using key: SymmetricKey, nonce: [UInt8]?, authenticatingData: A) throws -> QSealedBox where M: DataProtocol, A: DataProtocol
    static func decrypt<A>(_ sealedBox: QSealedBox, using key: SymmetricKey, authenticatingData authenticatedData: A) throws -> [UInt8] where A: DataProtocol
}

protocol QBlockCipher {
    associatedtype cipher: QCipher
    var key: SymmetricKey { get }
    var iv: [UInt8]? { get }
}

extension QBlockCipher {
    func seal<M, A>(message: M, packetNumber: [UInt8], authenticatingData: A) throws -> QSealedBox where M: DataProtocol, A: DataProtocol {
        let nonce: [UInt8]?
        if let iv = self.iv {
            nonce = self.generateNonce(packetNumber: packetNumber, iv: iv)
        } else {
            nonce = nil
        }
        return try cipher.encrypt(message: message, using: self.key, nonce: nonce, authenticatingData: authenticatingData)
    }

    func open<A>(_ sealedBox: QSealedBox, authenticatingData authenticatedData: A) throws -> [UInt8] where A: DataProtocol {
        try cipher.decrypt(sealedBox, using: self.key, authenticatingData: authenticatedData)
    }

    func open<A>(_ cipherText: ContiguousBytes, packetNumber: [UInt8], authenticatingData authenticatedData: A) throws -> [UInt8] where A: DataProtocol {
        var ct = cipherText.withUnsafeBytes { Data($0) }
        let tag = ct.suffix(16)
        ct = ct.dropLast(16)
        var nonce: [UInt8] = []
        if let iv = self.iv {
            nonce = self.generateNonce(packetNumber: packetNumber, iv: iv)
        }
        let sealedBox = GenericSealedBox(qNonce: nonce, tag: tag, ciphertext: ct)
        return try cipher.decrypt(sealedBox, using: self.key, authenticatingData: authenticatedData)
    }

    private func generateNonce(packetNumber: [UInt8], iv: [UInt8]) -> [UInt8] {
        return (Array(repeating: 0, count: 12 - packetNumber.count) + packetNumber).enumerated().map {
            $1 ^ iv[$0]
        }
    }
}

protocol QSealedBox {
    /// The authentication tag
    var tag: Data { get }

    /// The ciphertext
    var ciphertext: Data { get }

    /// The nonce used to seal this box
    var qNonce: [UInt8] { get }
}

extension QSealedBox {
    var combined: Data { ciphertext + tag }
}

struct GenericSealedBox: QSealedBox {
    let qNonce: [UInt8]
    let tag: Data
    var ciphertext: Data
}
