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
import Foundation

struct AESECBMaskCipher: QMaskCipher {
    typealias cipher = Crypto.AES.ECB
    let key: SymmetricKey

    init(key: SymmetricKey) {
        self.key = key
    }
}

extension Crypto.AES {
    /// Single Block AES ECB Permutations
    /// - Note: ECB doesn't use a Nonce nor does it support authenticating data.
    enum ECB: QMasker {
        static func generateMask<SAMPLE>(sample: SAMPLE, using key: SymmetricKey) throws -> [UInt8] where SAMPLE: ContiguousBytes {
            guard var ciphertext = sample as? Array<UInt8> else { throw Errors.Crypto(0) }
            try Crypto.AES.permute(&ciphertext, key: key)
            return ciphertext
        }

        /// Encrypts a single block of data using AES in ECB mode
        /// - Parameters:
        ///   - message: The plaintext to encrypt
        ///   - key: The key to use for encryption
        ///   - nonce: ECB doesn't support Nonces, any value passed in here will be discarded
        ///   - authenticatingData: ECB doesn't support AuthData, any value passed in here will be discarded
        /// - Returns: A SealedBox containing the encrypted data
        static func encrypt<M>(message: M, using key: SymmetricKey, nonce: [UInt8]?) throws -> [UInt8] where M: DataProtocol {
            guard var ciphertext = message as? Array<UInt8> else { throw Errors.Crypto(0) }
            try Crypto.AES.permute(&ciphertext, key: key)
            return ciphertext
        }

        /// Decrypts a single block of data using AES in ECB Mode
        /// - Parameters:
        ///   - sealedBox: The sealedbox containing the Ciphertext to be decrypted (note ECB doesn't support Nonce and Tags, these values will be discarded).
        ///   - key: The key used to decrypt the block
        ///   - authenticatedData: ECB doesn't support AuthData, any value passed in here will be discarded
        /// - Returns: The decrypted plaintext as a UInt8 byte Array.
        static func decrypt(_ sealedBox: QSealedBox, using key: SymmetricKey) throws -> [UInt8] {
            var plaintext = sealedBox.ciphertext
            try Crypto.AES.inversePermute(&plaintext, key: key)
            return plaintext.withUnsafeBytes { Array($0) }
        }
    }
}
