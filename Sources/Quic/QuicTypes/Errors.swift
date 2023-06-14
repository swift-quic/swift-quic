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

/// QUIC Errors
public enum Errors: Error {
    // TODO: Remove

    case NotYetImplemented

    // MARK: Custom Errors

    /// The `PacketType` doesn't belong to a specific `Epoch`
    case NoEpochAssociatedWithPacketType

    /// Unsupported Cipher Suite
    case UnsupportedCipherSuite(name: String)

    /// Unknown Cipher Suite
    case UnknownCipherSuite(code: [UInt8])

    /// The provided buffer is too short.
    case NotEnoughData

    /// This `Version` of Quic is unsupported
    case UnsupportedVersion

    /// The provided packet cannot be parsed because its `Version` is unknown.
    case UnknownVersion

    // MARK: Transport Errors (https://www.rfc-editor.org/rfc/rfc9000.html#section-20.1)

    /// An endpoint uses this with CONNECTION_CLOSE to signal that the connection is being closed abruptly in the absence of any error
    case Done

    /// The server refused to accept a new connection
    case Internal

    /// An endpoint received more data than it permitted in its advertised data limits
    case FlowControl

    /// An endpoint received a frame for a stream identifier that exceeded its advertised stream limit for the corresponding stream type
    case StreamLimit

    /// An endpoint received a frame for a stream that was not in a state that permitted that frame
    ///
    /// The stream ID is provided as associated data.
    case InvalidStreamState(UInt64)

    /// The received data exceeds the stream's final size.
    case FinalSize

    /// An endpoint received a frame that was badly formatted
    /// - example:  A frame of an unknown type or an ACK frame that has more acknowledgment ranges than the remainder of the packet could carry
    case FrameEncoding

    /// An endpoint received transport parameters that were badly formatted, included an invalid value, omitted a mandatory transport parameter, included a forbidden transport parameter, or were otherwise in error
    case InvalidTransportParam

    /// The number of connection IDs provided by the peer exceeds the advertised active_connection_id_limit
    case ConnectionIdLimit

    /// An endpoint detected an error with protocol compliance that was not covered by more specific error codes
    case ProtocolViolation

    /// A server received a client Initial that contained an invalid Token field
    case InvalidToken

    /// The application or application protocol caused the connection to be closed
    case Application

    /// A cryptographic operation failed.
    /// - 0x0D CryptoBufferExceeded
    /// - 0x0E KeyUpdateFailed
    /// - 0x0F AEAD Limit Reached
    /// - 0x0100 - 0x01FF Misc Crypto Errors (https://www.rfc-editor.org/rfc/rfc9001.pdf)
    case Crypto(UInt16)

    /// An endpoint has determined that the network path is incapable of supporting QUIC.
    /// An endpoint is unlikely to receive a CONNECTION_CLOSE frame carrying this code except when the path does not support a large enough MTU.
    case NoViablePath

    /// The provided packet cannot be parsed because it contains an invalid
    /// frame.
    case InvalidFrame

    /// The provided packet cannot be parsed.
    case InvalidPacket

    /// The operation cannot be completed because the connection is in an
    /// invalid state.
    case InvalidState

    // MARK: Application Protocol Errors (https://www.rfc-editor.org/rfc/rfc9000.html#section-20.2)

    /// The specified stream was stopped by the peer.
    ///
    /// The error code sent as part of the `STOP_SENDING` frame is provided as
    /// associated data.
    case StreamStopped(UInt64)

    /// The specified stream was reset by the peer.
    ///
    /// The error code sent as part of the `RESET_STREAM` frame is provided as
    /// associated data.
    case StreamReset(UInt64)

    /// Returns the Error code as its UInt64 code ready to be sent across the wire.
    func toWire() -> UInt64 {
        switch self {
            case .Done: return 0x00
            case .Internal: return 0x01
            case .FlowControl: return 0x03
            case .StreamLimit: return 0x04
            case .InvalidStreamState: return 0x05
            case .FinalSize: return 0x06
            case .InvalidFrame: return 0x07
            case .InvalidTransportParam: return 0x08
            case .ConnectionIdLimit: return 0x09
            case .ProtocolViolation: return 0x0a
            case .InvalidToken: return 0x0b
            case .Application: return 0x0c
            case .NoViablePath: return 0x10
            // Default to a generic ProtocolViolation
            default:
                return 0x0a
        }
    }
}
