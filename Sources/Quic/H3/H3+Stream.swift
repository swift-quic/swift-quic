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

extension HTTP3 {
    public static let HTTP3_CONTROL_STREAM_TYPE_ID: UInt64 = 0x00
    public static let HTTP3_PUSH_STREAM_TYPE_ID: UInt64 = 0x01
    public static let QPACK_ENCODER_STREAM_TYPE_ID: UInt64 = 0x02
    public static let QPACK_DECODER_STREAM_TYPE_ID: UInt64 = 0x03

    static let MAX_STATE_BUF_SIZE: UInt64 = (1 << 24) - 1

    public struct Stream {
        public enum `Type` {
            case Control
            case Request
            case Push
            case QpackEncoder
            case QpackDecoder
            case Unknown
        }

        public enum State {
            /// Reading the stream's type.
            case StreamType

            /// Reading the stream's current frame's type.
            case FrameType

            /// Reading the stream's current frame's payload length.
            case FramePayloadLen

            /// Reading the stream's current frame's payload.
            case FramePayload

            /// Reading DATA payload.
            case Data

            /// Reading the push ID.
            case PushId

            /// Reading a QPACK instruction.
            case QpackInstruction

            /// Reading and discarding data.
            case Drain

            /// All data has been read.
            case Finished
        }

        /// The corresponding transport stream's ID.
        let id: UInt64

        /// The stream's type (if known).
        let ty: HTTP3.Stream.`Type`?

        /// The current stream state.
        let state: HTTP3.Stream.State

        /// The buffer holding partial data for the current state.
        let state_buf: [UInt8]

        /// The expected amount of bytes required to complete the state.
        let state_len: UInt64

        /// The write offset in the state buffer, that is, how many bytes have
        /// already been read from the transport for the current state. When
        /// it reaches `stream_len` the state can be completed.
        let state_off: UInt64

        /// The type of the frame currently being parsed.
        let frame_type: UInt64?

        /// Whether the stream was created locally, or by the peer.
        let is_local: Bool

        /// Whether the stream has been remotely initialized.
        let remote_initialized: Bool

        /// Whether the stream has been locally initialized.
        let local_initialized: Bool

        /// Whether a `Data` event has been triggered for this stream.
        let data_event_triggered: Bool

        /// The last `PRIORITY_UPDATE` frame encoded field value, if any.
        let last_priority_update: [UInt8]?
    }
}
