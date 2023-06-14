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

// Retry Integrity Params
extension Version {
    static private let RETRY_INTEGRITY_KEY_V1: [UInt8] = [
        0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54,
        0xe3, 0x68, 0xc8, 0x4e,
    ]

    static private let RETRY_INTEGRITY_NONCE_V1: [UInt8] = [
        0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
    ]

    static private let RETRY_INTEGRITY_KEY_DRAFT29: [UInt8] = [
        0xcc, 0xce, 0x18, 0x7e, 0xd0, 0x9a, 0x09, 0xd0, 0x57, 0x28, 0x15, 0x5a,
        0x6c, 0xb9, 0x6b, 0xe1,
    ]

    static private let RETRY_INTEGRITY_NONCE_DRAFT29: [UInt8] = [
        0xe5, 0x49, 0x30, 0xf9, 0x7f, 0x21, 0x36, 0xf0, 0x53, 0x0a, 0x8c, 0x1c,
    ]

    /// Retry Integrity Nonce
    /// - Returns: The nonce to use when `Retry` is supported, nil otherwise
    public var retryIntegrityNonce: [UInt8]? {
        switch self {
            case .version1:
                return Version.RETRY_INTEGRITY_NONCE_V1
            case .versionDraft29:
                return Version.RETRY_INTEGRITY_NONCE_DRAFT29
            default:
                return nil
        }
    }

    /// Retry Integrity Key
    /// - Returns: The key to use when `Retry` is supported, nil otherwise
    public var retryIntegrityKey: [UInt8]? {
        switch self {
            case .version1:
                return Version.RETRY_INTEGRITY_KEY_V1
            case .versionDraft29:
                return Version.RETRY_INTEGRITY_KEY_DRAFT29
            default:
                return nil
        }
    }
}
