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
import XCTest
@testable import Quic

final class ConfigTests: XCTestCase {

    func testDecodeTransportParameters() throws {
        var tpBytes = try ByteBuffer(hexString: "0104800075300408ffffffffffffffff05048000ffff06048000ffff07048000ffff0801100901100f088394c8f03e515708")
        // 01 04 80007530
        // 04 08 ffffffffffffffff
        // 05 04 8000ffff
        // 06 04 8000ffff
        // 07 04 8000ffff
        // 08 01 10
        // 09 01 10
        // 0f 08 8394c8f03e515708
        let transportParameters = try TransportParams.decode(&tpBytes, perspective: .client)

        XCTAssertEqual(transportParameters.max_idle_timeout, 30000)
        XCTAssertEqual(transportParameters.initial_max_data, 4611686018427387903)
        XCTAssertEqual(transportParameters.initial_max_stream_data_bidi_local, 65535)
        XCTAssertEqual(transportParameters.initial_max_stream_data_bidi_remote, 65535)
        XCTAssertEqual(transportParameters.initial_max_stream_data_uni, 65535)
        XCTAssertEqual(transportParameters.initial_max_streams_bidi, 0x10)
        XCTAssertEqual(transportParameters.initial_max_streams_uni, 0x10)
        XCTAssertEqual(transportParameters.initial_source_connection_id, ConnectionID(with: try Array(hexString: "8394c8f03e515708")))
    }

    func testVarInt() throws {
        let expected: UInt64 = 23_421
        let num: [UInt8] = [128, 0, 91, 125]

        let buf = writeQuicVarInt( UInt64(23_421) )
        XCTAssertEqual(buf, [128, 91, 125])
        XCTAssertEqual(buf.readQuicVarInt(), expected)

        let buf4Bytes = writeQuicVarInt( UInt64(23_421), minBytes: 4 )
        XCTAssertEqual(buf4Bytes, num)
        XCTAssertEqual(buf4Bytes.readQuicVarInt(), expected)

        let varInt2 = VarInt(rawValue: 23_421)
        print(varInt2?.withUnsafeBytes({ Array($0) }))

        let varInt3 = VarInt(with: [128, 0, 91, 125])
        print(varInt3.withUnsafeBytes({ Array($0) }))
        XCTAssertEqual(varInt3.rawValue, expected)
        XCTAssertEqual(varInt3.withUnsafeBytes({ Array($0) }), [128, 0, 91, 125])

        let varInt4 = VarInt(with: [128, 91, 125])
        print(varInt4.withUnsafeBytes({ Array($0) }))
        XCTAssertEqual(varInt4.rawValue, expected)
        XCTAssertEqual(varInt4.withUnsafeBytes({ Array($0) }), [128, 0, 91, 125])
    }

    func testTransportParamsServerEncodesClientDecodes() throws {
        // Server encodes, client decodes.
        let tp = TransportParams(
            original_destination_connection_id: nil,
            max_idle_timeout: 30,
            stateless_reset_token: Array(repeating: 0xba, count: 16),
            max_udp_payload_size: 23_421,
            initial_max_data: 424_645_563,
            initial_max_stream_data_bidi_local: 154_323_123,
            initial_max_stream_data_bidi_remote: 6_587_456,
            initial_max_stream_data_uni: 2_461_234,
            initial_max_streams_bidi: 12_231,
            initial_max_streams_uni: 18_473,
            ack_delay_exponent: 20,
            max_ack_delay: (UInt64(2) << 14) - 1,
            disable_active_migration: true,
            active_conn_id_limit: 8,
            initial_source_connection_id: ConnectionID(with: Array("woot woot".utf8)),
            retry_source_connection_id: ConnectionID(with: Array("retry".utf8)),
            max_datagram_frame_size: 32
        )

        var rawServerParams = try tp.encode(perspective: .server)
        XCTAssertEqual(rawServerParams.readableBytes, 95) // Go requires minimum VarInt byte lengths for certain params (which result in 95 bytes). The Quiche tests expect 94
        print(rawServerParams.readableBytesView.hexString)

        let clientRecoveredParams = try TransportParams.decode(&rawServerParams, perspective: .client)
        XCTAssertEqual(clientRecoveredParams, tp)
    }

    func testTransportParamsClientEncodesServerDecodes() throws {
        // Client encodes, server decodes.
        let tp = TransportParams(
            original_destination_connection_id: nil,
            max_idle_timeout: 30,
            stateless_reset_token: nil,
            max_udp_payload_size: 23_421,
            initial_max_data: 424_645_563,
            initial_max_stream_data_bidi_local: 154_323_123,
            initial_max_stream_data_bidi_remote: 6_587_456,
            initial_max_stream_data_uni: 2_461_234,
            initial_max_streams_bidi: 12_231,
            initial_max_streams_uni: 18_473,
            ack_delay_exponent: 20,
            max_ack_delay: (UInt64(2) << 14) - 1,
            disable_active_migration: true,
            active_conn_id_limit: 8,
            initial_source_connection_id: ConnectionID(with: Array("woot woot".utf8)),
            retry_source_connection_id: nil,
            max_datagram_frame_size: 32
        )

        var rawClientParams = try tp.encode(perspective: .client)
        XCTAssertEqual(rawClientParams.readableBytes, 70) // Go requires minimum VarInt byte lengths for certain params (which result in 70 bytes). The Quiche tests expect 69
        print(rawClientParams.readableBytesView.hexString)

        let recoveredParams = try TransportParams.decode(&rawClientParams, perspective: .server)
        XCTAssertEqual(recoveredParams, tp)
    }
}
