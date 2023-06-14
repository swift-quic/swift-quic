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

public struct HeaderByteInspector {
    var byte: UInt8
    var form: Quic.HeaderForm
    var fixedBit: UInt8?
    var reservedBits: UInt8?
    var unusedBits: UInt8?

    /// Params for Long Packets
    var type: Quic.LongPacketType?
    var packetNumberLength: PacketNumberLength?

    /// Params for Short Packets
    var spinBit: UInt8?
    var keyPhase: UInt8?

    init(_ byte: UInt8) {
        self.byte = byte
        self.form = HeaderForm(rawValue: byte & HeaderForm.mask)!

        switch self.form {
            case .short:
                self.fixedBit = byte & 0b0100_0000
                self.spinBit = byte & 0b0010_0000
                self.reservedBits = byte & 0b0001_1000
                self.keyPhase = byte & 0b0000_0100
                self.packetNumberLength = PacketNumberLength(rawValue: byte & PacketNumberLength.mask)!
            case .long:
                self.type = LongPacketType(rawValue: byte & LongPacketType.mask)!
                switch self.type {
                    case .initial, .zeroRTT, .handshake:
                        self.fixedBit = byte & 0b0100_0000
                        self.reservedBits = byte & 0b0000_1100
                        self.packetNumberLength = PacketNumberLength(rawValue: byte & PacketNumberLength.mask)!
                    case .retry:
                        self.fixedBit = byte & 0b0100_0000
                        self.unusedBits = byte & 0b0000_1111
                    case .none:
                        print("Unknown Type")
                }
        }
    }

    func inspect() {
        HeaderByteInspector.inspectFirstByte(self.byte)
    }

    static func binary(_ byte: UInt8, start: Int, end: Int) -> String {
        var chars = byte.binaryString.map { "\($0)" }
        chars.insert("[", at: start)
        chars.insert("]", at: end + 1)
        return chars.joined()
    }

    static func inspectFirstByte(_ byte: UInt8) {
        var rows: [[String]] = []

        switch Quic.HeaderForm(rawValue: byte & Quic.HeaderForm.mask) {
            case .long:
                switch Quic.LongPacketType(rawValue: byte & Quic.LongPacketType.mask) {
                    case .initial, .zeroRTT, .handshake:
                        let topRow = ["Form", "Fixed Bit", "Type", "Reserved", "Packet Number Length"]
                        rows.append(topRow)
                        rows.append([
                            self.binary(byte, start: 0, end: 1),
                            self.binary(byte, start: 1, end: 2),
                            self.binary(byte, start: 2, end: 4),
                            self.binary(byte, start: 4, end: 6),
                            self.binary(byte, start: 6, end: 8)
                        ])
                        rows.append([
                            "\(Quic.HeaderForm(rawValue: byte & Quic.HeaderForm.mask)!)",
                            "\(byte & 0b0100_0000 >> 6) - \((byte & 0b0100_0000 >> 6) == 1 ? "Valid" : "Invalid")",
                            "\(Quic.LongPacketType(rawValue: byte & Quic.LongPacketType.mask)!)",
                            "\(byte & 0b0000_1100) - \((byte & 0b0000_1100) == 0 ? "Valid" : "Invalid")",
                            "\(Quic.PacketNumberLength(rawValue: byte & Quic.PacketNumberLength.mask)!.bytesToRead) bytes"
                        ])
                    case .retry:
                        let topRow = ["Form", "Fixed Bit", "Type", "Unused"]
                        rows.append(topRow)
                        rows.append([
                            self.binary(byte, start: 0, end: 1),
                            self.binary(byte, start: 1, end: 2),
                            self.binary(byte, start: 2, end: 4),
                            self.binary(byte, start: 4, end: 8)
                        ])
                        rows.append([
                            "\(Quic.HeaderForm(rawValue: byte & Quic.HeaderForm.mask)!)",
                            "\(byte & 0b0100_0000)",
                            "\(Quic.LongPacketType(rawValue: byte & Quic.LongPacketType.mask)!)",
                            "Unused"
                        ])
                    case .none:
                        print("Unknow Type")
                        return
                }

            case .short:
                let topRow = ["Form", "Fixed Bit", "Spin", "Reserved", "Key Phase", "Packet Number Length"]
                rows.append(topRow)
                rows.append([
                    self.binary(byte, start: 0, end: 1),
                    self.binary(byte, start: 1, end: 2),
                    self.binary(byte, start: 2, end: 3),
                    self.binary(byte, start: 3, end: 5),
                    self.binary(byte, start: 5, end: 6),
                    self.binary(byte, start: 6, end: 8)
                ])
                rows.append([
                    "\(Quic.HeaderForm(rawValue: byte & Quic.HeaderForm.mask)!)",
                    "\(byte & 0b0100_0000)",
                    "\(byte & 0b0010_0000)",
                    "\(byte & 0b0001_1000)",
                    "\(byte & 0b0000_0100)",
                    "\(Quic.PacketNumberLength(rawValue: byte & Quic.PacketNumberLength.mask)!.bytesToRead)",
                ])

            case .none:
                print("Unknown Header Form")
                return
        }

        outputASCIITable(rows)
    }
}
