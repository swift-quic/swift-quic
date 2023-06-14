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

public enum HTTP3 {
    public static let DATA_FRAME_TYPE_ID: UInt64 = 0x00
    public static let HEADERS_FRAME_TYPE_ID: UInt64 = 0x01
    public static let CANCEL_PUSH_FRAME_TYPE_ID: UInt64 = 0x03
    public static let SETTINGS_FRAME_TYPE_ID: UInt64 = 0x04
    public static let PUSH_PROMISE_FRAME_TYPE_ID: UInt64 = 0x05
    public static let GOAWAY_FRAME_TYPE_ID: UInt64 = 0x06
    public static let MAX_PUSH_FRAME_TYPE_ID: UInt64 = 0x0D
    public static let PRIORITY_UPDATE_FRAME_REQUEST_TYPE_ID: UInt64 = 0x0F0700
    public static let PRIORITY_UPDATE_FRAME_PUSH_TYPE_ID: UInt64 = 0x0F0701

    public static let SETTINGS_QPACK_MAX_TABLE_CAPACITY: UInt64 = 0x01
    public static let SETTINGS_MAX_FIELD_SECTION_SIZE: UInt64 = 0x06
    public static let SETTINGS_QPACK_BLOCKED_STREAMS: UInt64 = 0x07
    public static let SETTINGS_ENABLE_CONNECT_PROTOCOL: UInt64 = 0x08
    public static let SETTINGS_H3_DATAGRAM: UInt64 = 0x0276

    static let MAX_SETTINGS_PAYLOAD_SIZE: UInt64 = 256

    public typealias UInt128 = (UInt64, UInt64)
    public typealias ID = UInt64

    public struct Settings {
        let max_field_section_size: UInt64?
        let qpack_max_table_capacity: UInt64?
        let qpack_blocked_streams: UInt64?
        let connect_protocol_enabled: UInt64?
        let h3_datagram: UInt64?
        let grease: UInt128?
        let raw: [UInt128]
    }
}
