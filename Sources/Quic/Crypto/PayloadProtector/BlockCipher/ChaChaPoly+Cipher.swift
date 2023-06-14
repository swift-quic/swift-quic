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

public struct ChaChaPolyCipher: QBlockCipher {
    typealias cipher = ChaChaPoly
    let key: SymmetricKey
    let iv: [UInt8]?

    init(key: SymmetricKey, iv: [UInt8]? = nil) {
        self.key = key
        self.iv = iv
    }
}

extension Crypto.ChaChaPoly: QCipher {
    static func encrypt<M, A>(message: M, using key: SymmetricKey, nonce: [UInt8]? = nil, authenticatingData: A) throws -> QSealedBox where M: DataProtocol, A: DataProtocol {
        if let nonce = nonce {
            let n = try ChaChaPoly.Nonce(data: nonce)
            return try ChaChaPoly.seal(message, using: key, nonce: n, authenticating: authenticatingData)
        }
        return try ChaChaPoly.seal(message, using: key, authenticating: authenticatingData)
    }

    static func decrypt<A>(_ sealedBox: QSealedBox, using key: SymmetricKey, authenticatingData authenticatedData: A) throws -> [UInt8] where A: DataProtocol {
        let sealed = try ChaChaPoly.SealedBox(nonce: ChaChaPoly.Nonce(data: sealedBox.qNonce), ciphertext: sealedBox.ciphertext, tag: sealedBox.tag)
        return try ChaChaPoly.open(sealed, using: key, authenticating: authenticatedData).withUnsafeBytes { Array($0) }
    }
}

extension Crypto.ChaChaPoly.SealedBox: QSealedBox {
    var qNonce: [UInt8] { self.nonce.withUnsafeBytes { Array($0) } }
}
