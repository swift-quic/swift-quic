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

enum Frames:Equatable {
    case raw(Raw)
    case padding(Padding)
    case ping(Ping)
    case ack(ACK)
    case resetStream(ResetStream)
    case stopSending(StopSending)
    case crypto(Crypto)
    case newToken(NewToken)
    case stream(Stream)
    case maxData(MaxData)
    case maxStreamData(MaxStreamData)
    case maxStreams(MaxStreams)
    case dataBlocked(DataBlocked)
    case streamDataBlocked(StreamDataBlocked)
    case streamsBlocked(StreamsBlocked)
    case newConnectionID(NewConnectionID)
    case retireConnectionID(RetireConnectionID)
    case pathChallenge(PathChallenge)
    case pathResponse(PathResponse)
    case connectionClose(ConnectionClose)
    case handshakeDone(HandshakeDone)
}

extension Frames {
    struct Raw: Frame {
        static var type: UInt8 = UInt8.max
        var type: UInt8 { Self.type }
        let bytes: [UInt8]

        func encode(into buffer: inout ByteBuffer) {
            buffer.writeBytes(self.bytes)
        }
    }

    /// A PADDING frame (type=0x00) has no semantic value.
    /// - Note: PADDING frames can be used to increase the size of a packet.
    /// - Note: Padding can be used to increase an Initial packet to the minimum required size or to provide protection against traffic analysis for protected packets
    /// ```
    /// PADDING Frame {
    ///   Type (i) = 0x00,
    /// }
    /// ```
    struct Padding: Frame {
        static var type: UInt8 = 0x00
        var type: UInt8 { Self.type }
        let length: Int

        func encode(into buffer: inout ByteBuffer) {
            buffer.writeRepeatingByte(type, count: self.length)
        }
    }

    /// Endpoints can use PING frames (type=0x01) to verify that their peers are still alive or to check reachability to the peer
    /// - Note: The receiver of a PING frame simply needs to acknowledge the packet containing this frame
    /// - Note: The PING frame can be used to keep a connection alive when an application or application protocol wishes to prevent the connection from timing out
    /// ```
    /// PING Frame {
    ///   Type (i) = 0x01,
    /// }
    /// ```
    struct Ping: Frame {
        static var type: UInt8 = 0x01
        var type: UInt8 { Self.type }

        func encode(into buffer: inout ByteBuffer) {
            buffer.writeInteger(self.type)
        }
    }

    /// Receivers send ACK frames (types 0x02 and 0x03) to inform senders of packets they have received and processed. The ACK frame contains one or more ACK Ranges
    ///
    /// ```
    /// ACK Frame {
    ///   Type (i) = 0x02..0x03,
    ///   Largest Acknowledged (i),
    ///   ACK Delay (i),
    ///   ACK Range Count (i),
    ///   First ACK Range (i),
    ///   ACK Range (..) ...,
    ///   [ECN Counts (..)],
    /// }
    /// ```
    struct ACK: Frame {
        var type: UInt8 { self.ecnCounts == nil ? 0x02 : 0x03 }
        /// A variable-length integer representing the largest packet number the peer is acknowledging
        let largestAcknowledged: VarInt
        /// A variable-length integer encoding the acknowledgment delay in microseconds
        let delay: VarInt
        /// A variable-length integer indicating the number of contiguous packets preceding the Largest Acknowledged that are being acknowledged
        let firstAckRange: VarInt
        /// Contains additional ranges of packets that are alternately not acknowledged (Gap) and acknowledged (ACK Range)
        let ranges: [ACKRange]
        /// The three ECN counts
        let ecnCounts: ECNCounts?

        /// Each ACK Range consists of alternating Gap and ACK Range Length values in descending packet number order.
        /// - Note: ACK Ranges can be repeated.
        /// - Note: The number of Gap and ACK Range Length values is determined by the ACK Range Count field; one of each value is present for each value in the ACK Range Count field
        /// ```
        /// ACK Range {
        ///   Gap (i),
        ///   ACK Range Length (i),
        /// }
        /// ```
        struct ACKRange: Equatable {
            /// A variable-length integer indicating the number of contiguous unacknowledged packets preceding the packet number one lower than the smallest in the preceding ACK Range
            let gap: VarInt
            /// A variable-length integer indicating the number of contiguous acknowledged packets preceding the largest packet number, as determined by the preceding Gap
            let rangeLength: VarInt

            func encode(into buffer: inout ByteBuffer) {
                buffer.writeBytes(self.gap.withUnsafeBytes({ $0 }))
                buffer.writeBytes(self.rangeLength.withUnsafeBytes({ $0 }))
            }
        }

        /// The ACK frame uses the least significant bit of the type value (that is, type 0x03) to indicate ECN feedback and report receipt of QUIC packets with associated ECN codepoints of ECT(0), ECT(1), or ECN-CE in the packet's IP header.
        /// - Note: ECN counts are only present when the ACK frame type is 0x03
        /// - Note: ECN counts are maintained separately for each packet number space
        /// ```
        /// ECN Counts {
        ///   ECT0 Count (i),
        ///   ECT1 Count (i),
        ///   ECN-CE Count (i),
        /// }
        /// ```
        struct ECNCounts: Equatable {
            /// A variable-length integer representing the total number of packets received with the ECT(0) codepoint in the packet number space of the ACK frame
            let ect0: VarInt
            /// A variable-length integer representing the total number of packets received with the ECT(1) codepoint in the packet number space of the ACK frame
            let ect1: VarInt
            /// A variable-length integer representing the total number of packets received with the ECN-CE codepoint in the packet number space of the ACK frame
            let ecnCE: VarInt

            func encode(into buffer: inout ByteBuffer) {
                buffer.writeBytes(self.ect0.withUnsafeBytes({ $0 }))
                buffer.writeBytes(self.ect1.withUnsafeBytes({ $0 }))
                buffer.writeBytes(self.ecnCE.withUnsafeBytes({ $0 }))
            }
        }

        func encode(into buffer: inout ByteBuffer) {
            buffer.writeInteger(self.type)
            buffer.writeBytes(self.largestAcknowledged.withUnsafeBytes({ $0 }))
            buffer.writeBytes(self.delay.withUnsafeBytes({ $0 }))
            buffer.writeQuicVarInt(UInt64(self.ranges.count), minBytes: 1)
            buffer.writeBytes(self.firstAckRange.withUnsafeBytes({ $0 }))
            for range in self.ranges {
                range.encode(into: &buffer)
            }
            if let ecnCounts {
                ecnCounts.encode(into: &buffer)
            }
        }
    }

    /// An endpoint uses a RESET_STREAM frame (type=0x04) to abruptly terminate the sending part of a stream
    ///
    /// ```
    /// RESET_STREAM Frame {
    ///   Type (i) = 0x04,
    ///   Stream ID (i),
    ///   Application Protocol Error Code (i),
    ///   Final Size (i),
    /// }
    /// ```
    struct ResetStream: Frame {
        static var type: UInt8 = 0x04
        var type: UInt8 { Self.type }
        /// A variable-length integer encoding of the stream ID of the stream being terminated
        let streamID: StreamID
        /// A variable-length integer containing the application protocol error code (see Section 20.2) that indicates why the stream is being closed
        let applicationProtocolErrorCode: VarInt
        /// A variable-length integer indicating the final size of the stream by the RESET_STREAM sender, in units of bytes
        let finalSize: VarInt

        func encode(into buffer: inout ByteBuffer) {
            buffer.writeInteger(self.type)
            buffer.writeBytes(self.streamID.withUnsafeBytes( { $0 }))
            buffer.writeBytes(self.applicationProtocolErrorCode.withUnsafeBytes( { $0 }))
            buffer.writeBytes(self.finalSize.withUnsafeBytes( { $0 }))
        }
    }

    /// An endpoint uses a STOP_SENDING frame (type=0x05) to communicate that incoming data is being discarded on receipt per application request. STOP_SENDING requests that a peer cease transmission on a stream
    ///
    /// ```
    /// STOP_SENDING Frame {
    ///   Type (i) = 0x05,
    ///   Stream ID (i),
    ///   Application Protocol Error Code (i),
    /// }
    /// ```
    struct StopSending: Frame {
        static var type: UInt8 = 0x05
        var type: UInt8 { Self.type }
        /// A variable-length integer carrying the stream ID of the stream being ignored
        let streamID: StreamID
        /// A variable-length integer containing the application-specified reason the sender is ignoring the stream
        let applicationProtocolErrorCode: VarInt

        func encode(into buffer: inout ByteBuffer) {
            buffer.writeInteger(self.type)
            buffer.writeBytes(self.streamID.withUnsafeBytes( { $0 }))
            buffer.writeBytes(self.applicationProtocolErrorCode.withUnsafeBytes( { $0 }))
        }
    }

    /// A CRYPTO frame (type=0x06) is used to transmit cryptographic handshake messages. It can be sent in all packet types except 0-RTT.
    /// The CRYPTO frame offers the cryptographic protocol an in-order stream of bytes.
    ///
    /// CRYPTO frames are functionally identical to STREAM frames, except that they
    /// - do not bear a stream identifier;
    /// - they are not flow controlled;
    /// - and they do not carry markers for optional offset, optional length, and the end of the stream
    ///
    /// ```
    /// CRYPTO Frame {
    ///   Type (i) = 0x06,
    ///   Offset (i),
    ///   Length (i),
    ///   Crypto Data (..),
    /// }
    /// ```
    struct Crypto: Frame {
        static var type: UInt8 = 0x06
        var type: UInt8 { Self.type }
        /// A variable-length integer specifying the byte offset in the stream for the data in this CRYPTO frame.
        let offset: VarInt
        /// A variable-length integer specifying the length of the Crypto Data field in this CRYPTO frame
        var length: VarInt
        /// The cryptographic message data
        let data: [UInt8]

        init(offset: VarInt, data: [UInt8]) {
            self.offset = offset
            self.length = VarInt(integerLiteral: UInt64(data.count))
            self.data = data
        }

        func encode(into buffer: inout ByteBuffer) {
            buffer.writeInteger(self.type)
            buffer.writeBytes(self.offset.withUnsafeBytes( { $0 }))
            buffer.writeBytes(self.length.withUnsafeBytes( { $0 }))
            buffer.writeBytes(self.data)
        }
    }

    /// A server sends a NEW_TOKEN frame (type=0x07) to provide the client with a token to send in the header of an Initial packet for a future connection
    ///
    /// ```
    /// NEW_TOKEN Frame {
    ///   Type (i) = 0x07,
    ///   Token Length (i),
    ///   Token (..),
    /// }
    /// ```
    struct NewToken: Frame {
        static var type: UInt8 = 0x07
        var type: UInt8 { Self.type }
        /// An opaque blob that the client can use with a future Initial packet.
        /// The token MUST NOT be empty.
        /// A client MUST treat receipt of a NEW_TOKEN frame with an empty Token field as a connection error of type FRAME_ENCODING_ERROR
        let token: [UInt8]

        func encode(into buffer: inout ByteBuffer) {
            buffer.writeInteger(self.type)
            buffer.writeQuicVarInt(UInt64(self.token.count))
            buffer.writeBytes(self.token)
        }
    }

    /// STREAM frames implicitly create a stream and carry stream data. The Type field in the STREAM frame takes the form 0b00001XXX (or the set of values from 0x08 to 0x0f).
    /// The three low-order bits of the frame type determine the fields that are present in the frame
    ///
    /// ```
    /// STREAM Frame {
    ///   Type (i) = 0x08..0x0f,
    ///   Stream ID (i),
    ///   [Offset (i)],
    ///   [Length (i)],
    ///   Stream Data (..),
    /// }
    /// ```
    struct Stream: Frame {
        var type: UInt8 {
            var byte: UInt8 = 0x08
            if self.offset != nil { byte |= 0x04 }
            if self.length != nil { byte |= 0x02 }
            if self.fin == true { byte |= 0x01 }
            return byte
        }

        var streamType: StreamType {
            self.streamID.encodedType
        }

        let streamID: StreamID
        let offset: VarInt?
        let length: VarInt?
        let fin: Bool
        let data: ByteBuffer

        func encode(into buffer: inout ByteBuffer) {
            buffer.writeInteger(self.type)
            buffer.writeBytes(self.streamID.withUnsafeBytes( { $0 }))
            if let offset { buffer.writeBytes(offset.withUnsafeBytes( { $0 })) }
            if let length { buffer.writeBytes(length.withUnsafeBytes( { $0 })) }
            buffer.writeBytes(self.data.readableBytesView)
        }
    }

    /// A MAX_DATA frame (type=0x10) is used in flow control to inform the peer of the maximum amount of data that can be sent on the connection as a whole
    ///
    /// ```
    /// MAX_DATA Frame {
    ///   Type (i) = 0x10,
    ///   Maximum Data (i),
    /// }
    /// ```
    struct MaxData: Frame {
        static var type: UInt8 = 0x10
        var type: UInt8 { Self.type }
        /// A variable-length integer indicating the maximum amount of data that can be sent on the entire connection, in units of bytes
        let maximumData: VarInt

        func encode(into buffer: inout ByteBuffer) {
            buffer.writeInteger(self.type)
            buffer.writeBytes(self.maximumData.withUnsafeBytes( { $0 }))
        }
    }

    /// A MAX_STREAM_DATA frame (type=0x11) is used in flow control to inform a peer of the maximum amount of data that can be sent on a stream
    ///
    /// ```
    /// MAX_STREAM_DATA Frame {
    ///   Type (i) = 0x11,
    ///   Stream ID (i),
    ///   Maximum Stream Data (i),
    /// }
    /// ```
    struct MaxStreamData: Frame {
        static var type: UInt8 = 0x11
        var type: UInt8 { Self.type }
        /// The stream ID of the affected stream, encoded as a variable-length integer
        let streamID: StreamID
        /// A variable-length integer indicating the maximum amount of data that can be sent on the identified stream, in units of bytes
        let maximumStreamData: VarInt

        func encode(into buffer: inout ByteBuffer) {
            buffer.writeInteger(self.type)
            buffer.writeBytes(self.streamID.withUnsafeBytes( { $0 }))
            buffer.writeBytes(self.maximumStreamData.withUnsafeBytes( { $0 }))
        }
    }

    /// A MAX_STREAMS frame (type=0x12 or 0x13) informs the peer of the cumulative number of streams of a given type it is permitted to open.
    /// A MAX_STREAMS frame with a type of 0x12 applies to bidirectional streams, and a MAX_STREAMS frame with a type of 0x13 applies to unidirectional streams
    ///
    /// ```
    /// MAX_STREAMS Frame {
    ///   Type (i) = 0x12..0x13,
    ///   Maximum Streams (i),
    /// }
    /// ```
    struct MaxStreams: Frame {
        enum StreamType: UInt8 {
            case bidirectional = 0x12
            case unidirectional = 0x13
        }

        var type: UInt8 { self.streamType.rawValue }
        let streamType: StreamType
        /// A count of the cumulative number of streams of the corresponding type that can be opened over the lifetime of the connection
        /// - Note: This value cannot exceed 2^60, as it is not possible to encode stream IDs larger than 2^62-1
        let maximumStreams: VarInt

        func encode(into buffer: inout ByteBuffer) {
            buffer.writeInteger(self.type)
            buffer.writeBytes(self.maximumStreams.withUnsafeBytes( { $0 }))
        }
    }

    /// A sender SHOULD send a DATA_BLOCKED frame (type=0x14) when it wishes to send data but is unable to do so due to connection-level flow control
    ///
    /// ```
    /// DATA_BLOCKED Frame {
    ///   Type (i) = 0x14,
    ///   Maximum Data (i),
    /// }
    /// ```
    struct DataBlocked: Frame {
        static var type: UInt8 = 0x14
        var type: UInt8 { Self.type }
        /// A variable-length integer indicating the offset of the stream at which the blocking occurred.
        let maximumData: VarInt

        func encode(into buffer: inout ByteBuffer) {
            buffer.writeInteger(self.type)
            buffer.writeBytes(self.maximumData.withUnsafeBytes( { $0 }))
        }
    }

    /// A sender SHOULD send a STREAM_DATA_BLOCKED frame (type=0x15) when it wishes to send data but is unable to do so due to stream-level flow control
    ///
    /// ```
    /// STREAM_DATA_BLOCKED Frame {
    ///   Type (i) = 0x15,
    ///   Stream ID (i),
    ///   Maximum Stream Data (i),
    /// }
    /// ```
    struct StreamDataBlocked: Frame {
        static var type: UInt8 = 0x15
        var type: UInt8 { Self.type }
        /// A variable-length integer indicating the stream that is blocked due to flow control.
        let streamID: StreamID
        /// A variable-length integer indicating the offset of the stream at which the blocking occurred.
        let maximumStreamData: VarInt

        func encode(into buffer: inout ByteBuffer) {
            buffer.writeInteger(self.type)
            buffer.writeBytes(self.streamID.withUnsafeBytes( { $0 }))
            buffer.writeBytes(self.maximumStreamData.withUnsafeBytes( { $0 }))
        }
    }

    /// A sender SHOULD send a STREAMS_BLOCKED frame (type=0x16 or 0x17) when it wishes to open a stream but is unable to do so due to the maximum stream limit set by its peer
    ///
    /// ```
    /// STREAMS_BLOCKED Frame {
    ///   Type (i) = 0x16..0x17,
    ///   Maximum Streams (i),
    /// }
    /// ```
    struct StreamsBlocked: Frame {
        enum StreamType: UInt8 {
            case bidirectional = 0x16
            case unidirectional = 0x17
        }

        var type: UInt8 { self.streamType.rawValue }
        let streamType: StreamType
        /// A variable-length integer indicating the maximum number of streams allowed at the time the frame was sent.
        /// This value cannot exceed 260, as it is not possible to encode stream IDs larger than 262-1.
        /// Receipt of a frame that encodes a larger stream ID MUST be treated as a connection error of type STREAM_LIMIT_ERROR or FRAME_ENCODING_ERROR
        let maximumStreams: VarInt

        func encode(into buffer: inout ByteBuffer) {
            buffer.writeInteger(self.type)
            buffer.writeBytes(self.maximumStreams.withUnsafeBytes( { $0 }))
        }
    }

    /// An endpoint sends a NEW_CONNECTION_ID frame (type=0x18) to provide its peer with alternative connection IDs that can be used to break linkability when migrating connections
    ///
    /// ```
    /// NEW_CONNECTION_ID Frame {
    ///   Type (i) = 0x18,
    ///   Sequence Number (i),
    ///   Retire Prior To (i),
    ///   Length (8),
    ///   Connection ID (8..160),
    ///   Stateless Reset Token (128),
    /// }
    /// ```
    struct NewConnectionID: Frame, Equatable {
        static let type: UInt8 = 0x18
        var type: UInt8 { Self.type }
        let sequenceNumber: VarInt
        let retirePriorTo: VarInt
        let connectionID: ConnectionID
        let statelessResetToken: [UInt8]

        func encode(into buffer: inout ByteBuffer) {
            buffer.writeInteger(self.type)
            buffer.writeBytes(self.sequenceNumber.withUnsafeBytes( { $0 }))
            buffer.writeBytes(self.retirePriorTo.withUnsafeBytes( { $0 }))
            buffer.writeInteger(UInt8(self.connectionID.length), endianness: .big, as: UInt8.self)
            buffer.writeBytes(self.connectionID.withUnsafeBytes( { $0 }))
            buffer.writeBytes(self.statelessResetToken)
        }
    }

    /// An endpoint sends a RETIRE_CONNECTION_ID frame (type=0x19) to indicate that it will no longer use a connection ID that was issued by its peer.
    /// This includes the connection ID provided during the handshake. Sending a RETIRE_CONNECTION_ID frame also serves as a request to the peer to send additional connection IDs for future use
    ///
    ///- Note: Retiring a connection ID invalidates the stateless reset token associated with that connection ID
    /// ```
    /// RETIRE_CONNECTION_ID Frame {
    ///   Type (i) = 0x19,
    ///   Sequence Number (i),
    /// }
    /// ```
    struct RetireConnectionID: Frame {
        static let type: UInt8 = 0x19
        var type: UInt8 { Self.type }
        let sequenceNumber: VarInt

        func encode(into buffer: inout ByteBuffer) {
            buffer.writeInteger(self.type)
            buffer.writeBytes(self.sequenceNumber.withUnsafeBytes( { $0 }))
        }
    }

    /// Endpoints can use PATH_CHALLENGE frames (type=0x1a) to check reachability to the peer and for path validation during connection migration
    ///
    /// ```
    /// PATH_CHALLENGE Frame {
    ///   Type (i) = 0x1a,
    ///   Data (64),
    /// }
    /// ```
    struct PathChallenge: Frame {
        static let type: UInt8 = 0x1a
        var type: UInt8 { Self.type }
        let data: [UInt8] // Could also be a UInt68

        func encode(into buffer: inout ByteBuffer) {
            buffer.writeInteger(self.type)
            buffer.writeBytes(self.data)
        }
    }

    /// A PATH_RESPONSE frame (type=0x1b) is sent in response to a PATH_CHALLENGE frame
    ///
    /// ```
    /// PATH_RESPONSE Frame {
    ///   Type (i) = 0x1b,
    ///   Data (64),
    /// }
    /// ```
    struct PathResponse: Frame {
        static let type: UInt8 = 0x1b
        var type: UInt8 { Self.type }
        let data: [UInt8] // Could also be a UInt68

        func encode(into buffer: inout ByteBuffer) {
            buffer.writeInteger(self.type)
            buffer.writeBytes(self.data)
        }
    }

    /// An endpoint sends a CONNECTION_CLOSE frame (type=0x1c or 0x1d) to notify its peer that the connection is being closed.
    /// The CONNECTION_CLOSE frame with a type of 0x1c is used to signal errors at only the QUIC layer, or the absence of errors (with the NO_ERROR code).
    /// The CONNECTION_CLOSE frame with a type of 0x1d is used to signal an error with the application that uses QUIC
    ///
    /// ```
    /// CONNECTION_CLOSE Frame {
    ///   Type (i) = 0x1c..0x1d,
    ///   Error Code (i),
    ///   [Frame Type (i)],
    ///   Reason Phrase Length (i),
    ///   Reason Phrase (..),
    /// }
    /// ```
    struct ConnectionClose: Frame {
        enum CloseType: UInt8 {
            case quic = 0x1c
            case application = 0x1d
        }

        var type: UInt8 { self.closeType.rawValue }
        let closeType: CloseType
        /// A variable-length integer that indicates the reason for closing this connection. A CONNECTION_CLOSE frame of type 0x1c uses codes from the space defined in Section 20.1. A CONNECTION_CLOSE frame of type 0x1d uses codes defined by the application protocol
        let errorCode: VarInt
        /// A variable-length integer encoding the type of frame that triggered the error. A value of 0 (equivalent to the mention of the PADDING frame) is used when the frame type is unknown. The application-specific variant of CONNECTION_CLOSE (type 0x1d) does not include this field
        let frameType: VarInt?
        /// Additional diagnostic information for the closure. This can be zero length if the sender chooses not to give details beyond the Error Code value.
        /// This SHOULD be a UTF-8 encoded string [RFC3629], though the frame does not carry information, such as language tags, that would aid comprehension by any entity other than the one that created the text
        let reasonPhrase: String

        func encode(into buffer: inout ByteBuffer) {
            buffer.writeInteger(self.type)
            buffer.writeBytes(self.errorCode.withUnsafeBytes( { $0 }))
            if let frameType { buffer.writeBytes(frameType.withUnsafeBytes( { $0 })) }
            buffer.writeQuicVarInt(UInt64(self.reasonPhrase.count)) // Is this a one to one char to byte mapping?
            buffer.writeString(self.reasonPhrase)
        }
    }

    /// The server uses a HANDSHAKE_DONE frame (type=0x1e) to signal confirmation of the handshake to the client
    ///
    ///- Note: A HANDSHAKE_DONE frame can only be sent by the server
    /// ```
    /// HANDSHAKE_DONE Frame {
    ///   Type (i) = 0x1e,
    /// }
    /// ```
    struct HandshakeDone: Frame {
        static let type: UInt8 = 0x1e
        var type: UInt8 { Self.type }

        func encode(into buffer: inout ByteBuffer) {
            buffer.writeInteger(self.type)
        }
    }
}
