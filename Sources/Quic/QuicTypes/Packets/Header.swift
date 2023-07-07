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

protocol Header: Sendable {
    var firstByte: UInt8 { get }
    var bytes: [UInt8] { get }
}

protocol LongHeader: Header {
    var version: Version { get }
    var destinationIDLength: UInt8 { get }
    var destinationID: ConnectionID { get }
    var sourceIDLength: UInt8 { get }
    var sourceID: ConnectionID { get }
}

protocol ShortHeader: Header {
    var destinationID: ConnectionID { get }
}

protocol TypedHeader: LongHeader {
    var type: LongPacketType { get }
}

extension TypedHeader {
    public var firstByte: UInt8 {
        if let np = self as? NumberedHeader {
            return HeaderForm.long.rawValue ^
                0b0100_0000 ^
                self.type.rawValue ^
                0b0000_0000 ^
                np.packetNumberLength.rawValue
        } else {
            return HeaderForm.long.rawValue ^
                0b0100_0000 ^
                self.type.rawValue ^
                0b0000_0000
        }
    }
}

protocol NumberedHeader: Header {
    var packetNumber: [UInt8] { get }
    var packetNumberOffset: Int { get }
}

extension NumberedHeader {
    var packetNumberLength: PacketNumberLength {
        guard let pnl = PacketNumberLength(length: self.packetNumberLengthByteCount) else { fatalError("invalid packet number length") }
        return pnl
    }

    var packetNumberLengthByteCount: UInt8 {
        return UInt8(self.packetNumber.count)
    }

    func packetNumberAsUInt64() -> UInt64 {
        UInt64(bytes: (Array<UInt8>(repeating: 0, count: 8 - packetNumber.count) + packetNumber).reversed())
    }
}

extension Header {
    var needsPacketProtection: Bool {
        let form = HeaderForm(rawValue: self.firstByte & HeaderForm.mask)
        //print("NeedsPacketProtection Check: Form \(form!)")
        switch form {
            case .short: return true
            case .long:
                let type = LongPacketType(rawValue: self.firstByte & LongPacketType.mask)
                //print("NeedsPacketProtection Check: Type \(type!)")
                switch type {
                    case .initial, .retry, .handshake:
                        return true
                    default:
                        return false
                }
            default:
                fatalError("Invalid Header Form")
        }
    }
}
