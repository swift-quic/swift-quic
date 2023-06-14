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

enum ConnectionParams {
    // Due to the fact that in fuzzing mode we use a zero-length AEAD tag (which
    // would normally be 16 bytes), we need to adjust the minimum payload size to
    // account for that.
    static let PAYLOAD_MIN_LEN = 20

    // PATH_CHALLENGE (9 bytes) + AEAD tag (16 bytes).
    static let MIN_PROBING_SIZE = 25

    static let MAX_AMPLIFICATION_FACTOR = 3

    // The maximum number of tracked packet number ranges that need to be acked.
    //
    // This represents more or less how many ack blocks can fit in a typical packet.
    static let MAX_ACK_RANGES = 68

    // The highest possible stream ID allowed.
    static let MAX_STREAM_ID: UInt64 = 1 << 60

    // The default max_datagram_size used in congestion control.
    static let MAX_SEND_UDP_PAYLOAD_SIZE: UInt64 = 1200

    // The default length of DATAGRAM queues.
    static let DEFAULT_MAX_DGRAM_QUEUE_LEN: UInt64 = 0

    // The DATAGRAM standard recommends either none or 65536 as maximum DATAGRAM
    // frames size. We enforce the recommendation for forward compatibility.
    static let MAX_DGRAM_FRAME_SIZE: UInt64 = 65536

    // The length of the payload length field.
    static let PAYLOAD_LENGTH_LEN = 2

    // The number of undecryptable that can be buffered.
    static let MAX_UNDECRYPTABLE_PACKETS = 10

    static let RESERVED_VERSION_MASK: UInt32 = 0xfafafafa

    // The default size of the receiver connection flow control window.
    static let DEFAULT_CONNECTION_WINDOW: UInt64 = 48 * 1024

    // The maximum size of the receiver connection flow control window.
    static let MAX_CONNECTION_WINDOW: UInt64 = 24 * 1024 * 1024

    // How much larger the connection flow control window need to be larger than
    // the stream flow control window.
    static let CONNECTION_WINDOW_FACTOR: Float64 = 1.5

    // How many probing packet timeouts do we tolerate before considering the path
    // validation as failed.
    static let MAX_PROBING_TIMEOUTS = 3
}
