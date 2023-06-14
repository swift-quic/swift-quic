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

extension HTTP3 {
    public enum Frame {
        case data(payload: [UInt8])
        case headers(block: [UInt8])
        case cancelPush(id: ID)
        case settings(HTTP3.Settings)
        case pushPromise(id: ID, headerBlock: [UInt8])
        case goAway(id: ID)
        case maxPushID(id: ID)
        case priorityUpdateRequest(elementID: ID, fieldValue: [UInt8])
        case priorityUpdatePush(elementID: ID, fieldValue: [UInt8])
        case unknown(rawType: UInt64, payloadLength: UInt64)

        init?(fromBytes bytes: [UInt8]) {
            guard !bytes.isEmpty else { return nil }
            var b = ByteBuffer(bytes: bytes)
            let type = b.readInteger(as: UInt64.self) //readBytes(length: 1)
            switch type {
                case DATA_FRAME_TYPE_ID:
                    guard let length = b.readVarInt() else { return nil }
                    guard let payload = b.readBytes(length: Int(length)) else { return nil }
                    self = .data(payload: payload)

                case HEADERS_FRAME_TYPE_ID:
                    guard let length = b.readVarInt() else { return nil }
                    guard let headerBlock = b.readBytes(length: Int(length)) else { return nil }
                    self = .headers(block: headerBlock)

                case CANCEL_PUSH_FRAME_TYPE_ID:
                    guard let length = b.readVarInt() else { return nil }
                    guard let id = b.readVarInt() else { return nil }
                    self = .cancelPush(id: id)

                case SETTINGS_FRAME_TYPE_ID:
                    print("TODO::H3:Frame -> Decode Settings Frame")
                    return nil

                case PUSH_PROMISE_FRAME_TYPE_ID:
                    guard let length = b.readVarInt() else { return nil }
                    //guard let id = b.readVarInt() else { return nil }
                    guard let (id, headerBlock) = b.readQuicVarIntLengthPrefixedBytesReturningVarInt() else { return nil }
                    self = .pushPromise(id: id, headerBlock: headerBlock)

                case GOAWAY_FRAME_TYPE_ID:
                    guard let length = b.readVarInt() else { return nil }
                    guard let id = b.readVarInt() else { return nil }
                    self = .goAway(id: id)

                case MAX_PUSH_FRAME_TYPE_ID:
                    guard let length = b.readVarInt() else { return nil }
                    guard let id = b.readVarInt() else { return nil }
                    self = .maxPushID(id: id)

                // PRIORITY_UPDATE_FRAME
                case 0x0F:
                    var buff = ByteBuffer(bytes: type!.bytes() + b.readBytes(length: 2)!)
                    var subType = buff.readInteger(as: UInt64.self)
                    switch subType {
                        case PRIORITY_UPDATE_FRAME_REQUEST_TYPE_ID:
                            guard let length = b.readVarInt() else { return nil }
                            guard let id = b.readVarInt() else { return nil }
                            guard let (id, fieldValue) = b.readQuicVarIntLengthPrefixedBytesReturningVarInt() else { return nil }
                            self = .priorityUpdateRequest(elementID: id, fieldValue: fieldValue)

                        case PRIORITY_UPDATE_FRAME_PUSH_TYPE_ID:
                            guard let length = b.readVarInt() else { return nil }
                            guard let id = b.readVarInt() else { return nil }
                            guard let (id, fieldValue) = b.readQuicVarIntLengthPrefixedBytesReturningVarInt() else { return nil }
                            self = .priorityUpdatePush(elementID: id, fieldValue: fieldValue)
                        default:
                            return nil
                    }

                default:
                    return nil
            }
        }

        func toBytes() -> [UInt8] {
            switch self {
                case .data(let payload):
                    var b = writeQuicVarInt(HTTP3.DATA_FRAME_TYPE_ID)
                    b += writeQuicVarInt(UInt64(payload.count))
                    b += payload
                    return b
                case .headers(let headerBlock):
                    var b = writeQuicVarInt(HTTP3.HEADERS_FRAME_TYPE_ID)
                    b += writeQuicVarInt(UInt64(headerBlock.count))
                    b += headerBlock
                    return b
                case .cancelPush(let id):
                    var b = writeQuicVarInt(HTTP3.CANCEL_PUSH_FRAME_TYPE_ID)
                    let varInt = writeQuicVarInt(id)
                    b += writeQuicVarInt(UInt64(varInt.count))
                    b += varInt
                    return b
                case .settings(let settings):
                    print("TODO: Encode Settings H3:Frame Type")
                    return []
                case .pushPromise(let pushID, let headerBlock):
                    let varInt = writeQuicVarInt(pushID)
                    var b = writeQuicVarInt(HTTP3.PUSH_PROMISE_FRAME_TYPE_ID)
                    b += writeQuicVarInt(UInt64(varInt.count + headerBlock.count))
                    b += varInt
                    b += headerBlock
                    return b
                case .goAway(let id):
                    var b = writeQuicVarInt(HTTP3.GOAWAY_FRAME_TYPE_ID)
                    let varInt = writeQuicVarInt(id)
                    b += writeQuicVarInt(UInt64(varInt.count))
                    b += varInt
                    return b
                case .maxPushID(let id):
                    var b = writeQuicVarInt(HTTP3.MAX_PUSH_FRAME_TYPE_ID)
                    let varInt = writeQuicVarInt(id)
                    b += writeQuicVarInt(UInt64(varInt.count))
                    b += varInt
                    return b
                case .priorityUpdateRequest(let elementID, let fieldValue):
                    let varInt = writeQuicVarInt(elementID)
                    var b = writeQuicVarInt(HTTP3.PRIORITY_UPDATE_FRAME_REQUEST_TYPE_ID)
                    b += writeQuicVarInt(UInt64(varInt.count + fieldValue.count))
                    b += varInt
                    b += fieldValue
                    return b
                case .priorityUpdatePush(let elementID, let fieldValue):
                    let varInt = writeQuicVarInt(elementID)
                    var b = writeQuicVarInt(HTTP3.PRIORITY_UPDATE_FRAME_PUSH_TYPE_ID)
                    b += writeQuicVarInt(UInt64(varInt.count + fieldValue.count))
                    b += varInt
                    b += fieldValue
                    return b
                case .unknown:
                    print("Error: Attempting to encode unknown H3:Frame Type")
                    return []
            }
        }
    }
}
