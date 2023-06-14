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

private extension ByteBuffer {
    mutating func readTransportParameter() throws -> TransportParameter {
        try self.rewindReaderOnError { `self` in
            guard let id = self.readQuicVarInt() else { throw TransportParams.Errors.failedToDecodeTransportParams("Failed to read ID") }
            guard let value = self.readQuicVarIntLengthPrefixedBytes() else { throw TransportParams.Errors.failedToDecodeTransportParams("Failed to read value for ID:\(id)") }
            return TransportParameter(id: id, value: value)
        }
    }
}

/// https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameter-encodin
/// ```
/// Transport Parameter {
///   Transport Parameter ID (i),
///   Transport Parameter Length (i),
///   Transport Parameter Value (..),
/// }
/// ```
struct TransportParameter {
    let id: UInt64
    let value: [UInt8]
}

struct TransportParams: Equatable {
    var original_destination_connection_id: ConnectionID?
    var max_idle_timeout: UInt64
    var stateless_reset_token: [UInt8]?
    var max_udp_payload_size: UInt64
    var initial_max_data: UInt64
    var initial_max_stream_data_bidi_local: UInt64
    var initial_max_stream_data_bidi_remote: UInt64
    var initial_max_stream_data_uni: UInt64
    var initial_max_streams_bidi: UInt64
    var initial_max_streams_uni: UInt64
    var ack_delay_exponent: UInt64
    var max_ack_delay: UInt64
    var disable_active_migration: Bool
    // pub preferred_address: ...,
    var active_conn_id_limit: UInt64
    var initial_source_connection_id: ConnectionID?
    var retry_source_connection_id: ConnectionID?
    var max_datagram_frame_size: UInt64?
    var preferredAddress: PreferredAddress?

    static var `default`: TransportParams {
        TransportParams(
            original_destination_connection_id: nil,
            max_idle_timeout: 0,
            stateless_reset_token: nil,
            max_udp_payload_size: 65527,
            initial_max_data: 0,
            initial_max_stream_data_bidi_local: 0,
            initial_max_stream_data_bidi_remote: 0,
            initial_max_stream_data_uni: 0,
            initial_max_streams_bidi: 0,
            initial_max_streams_uni: 0,
            ack_delay_exponent: 3,
            max_ack_delay: 25,
            disable_active_migration: false,
            active_conn_id_limit: 2,
            initial_source_connection_id: nil,
            retry_source_connection_id: nil,
            max_datagram_frame_size: nil,
            preferredAddress: nil
        )
    }

    /// https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameter-encodin
    /// ```
    /// Transport Parameter {
    ///   Transport Parameter ID (i),
    ///   Transport Parameter Length (i),
    ///   Transport Parameter Value (..),
    /// }
    /// ```
    static func decode(_ buffer: inout ByteBuffer, perspective: EndpointRole) throws -> TransportParams {
        var seenParams: [UInt64] = []
        var params = TransportParams.default

        while buffer.readableBytes > 0 {
            // Consume the next TransportParameter
            let param = try buffer.readTransportParameter()

            // Ensure we don't have duplicate parameter entries
            if seenParams.contains(param.id) {
                throw Errors.failedToDecodeTransportParams("Duplicate Param Found (\(param.id))")
            }
            seenParams.append(param.id)

            //print("ID:\(param.id) - Value Length: \(param.value.count)")

            switch param.id {
                case 0x0000:
                    if perspective == .server { throw Errors.invalidParams }

                    params.original_destination_connection_id = ConnectionID(with: param.value)

                case 0x0001:
                    guard let val = param.value.readQuicVarInt() else { throw Errors.invalidTransportParameter(param) }
                    params.max_idle_timeout = val

                case 0x0002:
                    if perspective == .server { throw Errors.invalidParams }

                    guard param.value.count == 16 else { throw Errors.invalidTransportParameter(param) }

                    params.stateless_reset_token = param.value

                case 0x0003:
                    guard let val = param.value.readQuicVarInt(), val >= 1200 else { print("Value: \(param.value.readQuicVarInt() ?? 0)"); throw Errors.invalidTransportParameter(param) }
                    params.max_udp_payload_size = val

                case 0x0004:
                    guard let val = param.value.readQuicVarInt() else { throw Errors.invalidTransportParameter(param) }
                    params.initial_max_data = val

                case 0x0005:
                    guard let val = param.value.readQuicVarInt() else { throw Errors.invalidTransportParameter(param) }
                    params.initial_max_stream_data_bidi_local = val

                case 0x0006:
                    guard let val = param.value.readQuicVarInt() else { throw Errors.invalidTransportParameter(param) }
                    params.initial_max_stream_data_bidi_remote = val

                case 0x0007:
                    guard let val = param.value.readQuicVarInt() else { throw Errors.invalidTransportParameter(param) }
                    params.initial_max_stream_data_uni = val

                case 0x0008:
                    guard let max = param.value.readQuicVarInt() else { throw Errors.invalidTransportParameter(param) }

                    if max > ConnectionParams.MAX_STREAM_ID { throw Errors.invalidTransportParameter(param) }

                    params.initial_max_streams_bidi = max

                case 0x0009:
                    guard let max = param.value.readQuicVarInt() else { throw Errors.invalidTransportParameter(param) }

                    if max > ConnectionParams.MAX_STREAM_ID { throw Errors.invalidTransportParameter(param) }

                    params.initial_max_streams_uni = max

                case 0x000a:
                    guard let ackDelayExp = param.value.readQuicVarInt(), ackDelayExp <= 20 else { throw Errors.invalidTransportParameter(param) }

                    params.ack_delay_exponent = ackDelayExp

                case 0x000b:
                    guard let maxAckDelay = param.value.readQuicVarInt(), maxAckDelay < (UInt64(2) << 14) else { throw Errors.invalidTransportParameter(param) }

                    params.max_ack_delay = maxAckDelay

                case 0x000c:
                    params.disable_active_migration = true

                case 0x000d:
                    if perspective == .server { throw Errors.invalidParams }

                    params.preferredAddress = try PreferredAddress(param.value)

                case 0x000e:
                    guard let limit = param.value.readQuicVarInt(), limit >= 2 else { throw Errors.invalidTransportParameter(param) }

                    params.active_conn_id_limit = limit

                case 0x000f:
                    params.initial_source_connection_id = ConnectionID(with: param.value)

                case 0x0010:
                    if perspective == .server { throw Errors.invalidParams }

                    params.retry_source_connection_id = ConnectionID(with: param.value)

                case 0x0020:
                    guard let val = param.value.readQuicVarInt() else { throw Errors.invalidTransportParameter(param) }
                    params.max_datagram_frame_size = val

                default:
                    // TODO: ignore unknown param ids? or throw an error?
                    print("TransportParams::Decode - Encountered Unknown Param ID \(param.id)")
                    // throw Errors.unknownTranportParam
            }
        }

        return params
    }

    func encode(perspective: EndpointRole) throws -> ByteBuffer {
        var buffer = ByteBuffer()

        // if we're the server append the original destination connection ID
        if perspective == .server, let odcid = original_destination_connection_id {
            self.encodeParam(buffer: &buffer, id: 0x0000, value: odcid.rawValue)
        }

        if self.max_idle_timeout != 0 {
            self.encodeParam(buffer: &buffer, id: 0x0001, value: writeQuicVarInt(self.max_idle_timeout))
        }

        // if we're the server and we have a stateless reset token, append it.
        if perspective == .server, let token = stateless_reset_token {
            self.encodeParam(buffer: &buffer, id: 0x0002, value: token)
        }

        if self.max_udp_payload_size != 0 {
            self.encodeParam(buffer: &buffer, id: 0x0003, value: writeQuicVarInt(self.max_udp_payload_size, minBytes: 4))
        }

        if self.initial_max_data != 0 {
            self.encodeParam(buffer: &buffer, id: 0x0004, value: writeQuicVarInt(self.initial_max_data, minBytes: 4))
        }

        if self.initial_max_stream_data_bidi_local != 0 {
            self.encodeParam(buffer: &buffer, id: 0x0005, value: writeQuicVarInt(self.initial_max_stream_data_bidi_local, minBytes: 4))
        }

        if self.initial_max_stream_data_bidi_remote != 0 {
            self.encodeParam(buffer: &buffer, id: 0x0006, value: writeQuicVarInt(self.initial_max_stream_data_bidi_remote, minBytes: 4))
        }

        if self.initial_max_stream_data_uni != 0 {
            self.encodeParam(buffer: &buffer, id: 0x0007, value: writeQuicVarInt(self.initial_max_stream_data_uni, minBytes: 4))
        }

        if self.initial_max_streams_bidi != 0 {
            self.encodeParam(buffer: &buffer, id: 0x0008, value: writeQuicVarInt(self.initial_max_streams_bidi))
        }

        if self.initial_max_streams_uni != 0 {
            self.encodeParam(buffer: &buffer, id: 0x0009, value: writeQuicVarInt(self.initial_max_streams_uni))
        }

        if self.ack_delay_exponent != 0 {
            self.encodeParam(buffer: &buffer, id: 0x000a, value: writeQuicVarInt(self.ack_delay_exponent))
        }

        if self.max_ack_delay != 0 {
            self.encodeParam(buffer: &buffer, id: 0x000b, value: writeQuicVarInt(self.max_ack_delay))
        }

        if self.disable_active_migration {
            self.encodeParam(buffer: &buffer, id: 0x000c, value: [0x00])
        }

        // TODO: Encode Preferred Address

        if self.active_conn_id_limit != 2 {
            self.encodeParam(buffer: &buffer, id: 0x000e, value: writeQuicVarInt(self.active_conn_id_limit))
        }

        if let scid = initial_source_connection_id {
            self.encodeParam(buffer: &buffer, id: 0x000f, value: scid.rawValue)
        }

        if perspective == .server, let retrySCID = retry_source_connection_id {
            self.encodeParam(buffer: &buffer, id: 0x0010, value: retrySCID.rawValue)
        }

        if let max_datagram_frame_size = max_datagram_frame_size {
            self.encodeParam(buffer: &buffer, id: 0x0020, value: writeQuicVarInt(max_datagram_frame_size))
        }

        return buffer
    }

    private func encodeParam(buffer: inout ByteBuffer, id: UInt16, value: [UInt8]) {
        buffer.writeQuicVarInt(UInt64(id), minBytes: 1)
        buffer.writeQuicVarInt(UInt64(value.count), minBytes: 1)
        buffer.writeBytes(value)
    }

    enum Errors: Error {
        case invalidParams
        case invalidTransportParameter(TransportParameter)
        case unknownTransportParam
        case failedToDecodeTransportParams(String)
    }

    struct PreferredAddress: Equatable {
        let ipv4: SocketAddress
        let ipv6: SocketAddress
        let connectionID: ConnectionID
        let statelessResetToken: [UInt8]

        /// Decodes a PreferredAddress from a string of Bytes
        /// ```
        /// Preferred Address {
        ///   IPv4 Address (32),
        ///   IPv4 Port (16),
        ///   IPv6 Address (128),
        ///   IPv6 Port (16),
        ///   Connection ID Length (8),
        ///   Connection ID (..),
        ///   Stateless Reset Token (128),
        /// }
        /// ```
        init(_ bytes: inout ByteBuffer) throws {
            guard let ipv4Address = bytes.readSlice(length: 4),
                  let ipv4Port = bytes.readInteger(as: UInt16.self),
                  let ipv6Address = bytes.readSlice(length: 16),
                  let ipv6Port = bytes.readInteger(as: UInt16.self),
                  let cidLength = bytes.readInteger(as: UInt8.self),
                  let cid = bytes.readBytes(length: Int(cidLength)),
                  let reset = bytes.readBytes(length: 16) else {
                throw Errors.invalidParams
            }

            self.ipv4 = try SocketAddress(packedIPAddress: ipv4Address, port: Int(ipv4Port))
            self.ipv6 = try SocketAddress(packedIPAddress: ipv6Address, port: Int(ipv6Port))
            self.connectionID = ConnectionID(with: cid)
            self.statelessResetToken = reset
        }

        init(_ bytes: [UInt8]) throws {
            var mutableByteBuffer = ByteBuffer(bytes: bytes)
            try self.init(&mutableByteBuffer)
        }

        // TODO: Encode
        //func encode() -> [UInt8] {
        //    var bytes:[UInt8] = []
        //    // Maybe sockaddr
        //
        //
        //}
    }
}
