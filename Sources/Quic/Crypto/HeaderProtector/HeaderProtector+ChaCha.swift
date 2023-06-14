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

struct ChaChaHeaderProtector: HeaderProtector {
    let sampleLength: Int = 16
    var cipher: any QMaskCipher

    init(cipherSuite: CipherSuite, trafficSecret: SymmetricKey, hkdfLabel: String) throws {
        let hpKey = try cipherSuite.expandLabel(pseudoRandomKey: trafficSecret, label: hkdfLabel, outputByteCount: cipherSuite.keyLength)
        self.cipher = ChaCha20CTRMaskCipher(key: hpKey)
    }
}
