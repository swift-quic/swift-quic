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
import NIOCore

extension Crypto.HKDF {

    /// Expands cryptographically strong key material into a derived symmetric key expanding upon the provided `label` using the implementation outlined in RFC8446.7.1
    static func expandLabel<PRK>(pseudoRandomKey: PRK, label: String, context: [UInt8] = [], outputByteCount: Int) throws -> SymmetricKey where PRK: ContiguousBytes {
        try Self.expand(
            pseudoRandomKey: pseudoRandomKey,
            info: Self.generateLabel(
                length: outputByteCount,
                label: label,
                hash: context
            ),
            outputByteCount: outputByteCount
        )
    }

    public enum Errors: Error {
        case invalidLabelCount
    }

    /// HKDFExpandLabel
    ///
    /// [RFC 8446 7.1](https://www.rfc-editor.org/rfc/rfc8446#section-7.1)
    /// [Reference Implementation](https://boringssl.googlesource.com/boringssl/+/HEAD/ssl/test/runner/prf.go)
    internal static func generateLabel(length: Int, label: String, hash: [UInt8]) throws -> [UInt8] {
        guard label.count <= 255, hash.count <= 255 else { throw Errors.invalidLabelCount }
        let versionLabel = "tls13 ".utf8
        var x: [UInt8] = []
        x.append(0)
        x.append(UInt8(length))
        x.append(UInt8(versionLabel.count + label.count))
        x.append(contentsOf: versionLabel)
        x.append(contentsOf: label.utf8)
        x.append(UInt8(hash.count))
        x.append(contentsOf: hash)
        return x
    }
}
