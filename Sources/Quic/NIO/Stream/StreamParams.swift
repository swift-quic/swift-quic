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

enum StreamParams {
    static let DEFAULT_URGENCY: UInt8 = 127

    static let SEND_BUFFER_SIZE: UInt64 = 4096

    // The default size of the receiver stream flow control window.
    static let DEFAULT_STREAM_WINDOW: UInt64 = 32 * 1024

    /// The maximum size of the receiver stream flow control window.
    static let MAX_STREAM_WINDOW: UInt64 = 16 * 1024 * 1024
}
