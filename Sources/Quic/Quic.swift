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

let currentVersion: Version = { .version1 }()

let supportedVersions: [Version] = { [.version1, .versionDraft29] }()

let knownVersions: [Version] = {
    [
        .version2,
        .version1,
        .versionDraft29,
    ]
}()

func isKnown(version: Version) -> Bool {
    knownVersions.contains(version)
}

func isSupported(version: Version) -> Bool {
    supportedVersions.contains(version)
}

let minDatagramSize = { 1200 }()
let maxConnectionIDLength = { 20 }()

protocol Frame: Sendable, Equatable {
    var type: UInt8 { get }
    func encode(into buffer: inout ByteBuffer)
}

extension Frame {
    var serializedByteCount: Int {
        self.serialized.readableBytes
    }

    var serialized: ByteBuffer {
        var buf = ByteBuffer()
        self.encode(into: &buf)
        return buf
    }
}
