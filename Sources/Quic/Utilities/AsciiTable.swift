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

import Foundation

/// Copied from Swift Vapor Project
func outputASCIITable(_ rows: [[String]]) {
    var columnWidths: [Int] = []

    // calculate longest columns
    for row in rows {
        for (i, column) in row.enumerated() {
            if columnWidths.count <= i {
                columnWidths.append(0)
            }
            if column.description.count > columnWidths[i] {
                columnWidths[i] = column.description.count
            }
        }
    }

    func hr() {
        var text: String = ""
        for columnWidth in columnWidths {
            text += "+"
            text += "-"
            for _ in 0..<columnWidth {
                text += "-"
            }
            text += "-"
        }
        text += "+"
        print(text)
    }

    for (i, row) in rows.enumerated() {
        if i % 3 == 0 { hr() }

        var text: String = ""
        for (i, column) in row.enumerated() {
            text += "| "
            text += column
            for _ in 0..<(columnWidths[i] - column.description.count) {
                text += " "
            }
            text += " "
        }
        text += "|"
        print(text)

        hr()
    }
}

extension UInt8 {
    var binaryString: String {
        String(self, radix: 2)
    }
}

extension Quic.Header {
    func inspectFirstByte() {
        HeaderByteInspector.inspectFirstByte(self.firstByte)
    }

    func inspect() {
        let byte = self.firstByte
        var rows: [[String]] = []

        switch Quic.HeaderForm(rawValue: byte & Quic.HeaderForm.mask) {
            case .long:
                switch Quic.LongPacketType(rawValue: byte & Quic.LongPacketType.mask) {
                    case .initial:
                        guard let initial = self as? InitialHeader else { print("Invalid Type"); return }
                        let topRow = [
                            "First Byte",
                            "Version",
                            "DCID Length",
                            "DCID",
                            "SCID Length",
                            "SCID",
                            "Token Length",
                            "Token",
                            "Length",
                            "Packet Number",
                            "Payload"
                        ]
                        rows.append(topRow)

                        rows.append([
                            byte.binaryString,
                            "\(initial.version)",
                            "\(initial.destinationIDLength)",
                            "\(initial.destinationID.rawValue.hexString)",
                            "\(initial.sourceIDLength)",
                            "\(initial.sourceID.rawValue.hexString)",
                            "\(initial.token.count)",
                            "\(initial.token.hexString)",
                            "\(initial.packetNumberLengthByteCount) + payload",
                            "\(initial.packetNumber.hexString)",
                            "payload"
                        ])
                    case .handshake:
                        guard let handshake = self as? HandshakeHeader else { print("Invalid Type"); return }
                        let topRow = [
                            "First Byte",
                            "Version",
                            "DCID Length",
                            "DCID",
                            "SCID Length",
                            "SCID",
                            "Length",
                            "Packet Number",
                            "Payload"
                        ]
                        rows.append(topRow)

                        rows.append([
                            byte.binaryString,
                            "\(handshake.version)",
                            "\(handshake.destinationIDLength)",
                            "\(handshake.destinationID.rawValue.hexString)",
                            "\(handshake.sourceIDLength)",
                            "\(handshake.sourceID.rawValue.hexString)",
                            "\(handshake.packetNumberLengthByteCount) + payload",
                            "\(handshake.packetNumber.hexString)",
                            "payload"
                        ])
                    case .zeroRTT:
                        let topRow = [
                            "First Byte",
                            "Version",
                            "DCID Length",
                            "DCID",
                            "SCID Length",
                            "SCID",
                            "Length",
                            "Packet Number",
                            "Payload"
                        ]
                        rows.append(topRow)
                        rows.append([
                            byte.binaryString,
                        ])

                    case .retry:
                        let topRow = [
                            "First Byte",
                            "Version",
                            "DCID Length",
                            "DCID",
                            "SCID Length",
                            "SCID",
                            "Retry Token",
                            "Retry Tag",
                        ]
                        rows.append(topRow)
                        rows.append([
                            byte.binaryString,
                        ])

                    case .none:
                        print("Unknow Type")
                        return
                }

            case .short:
                let topRow = ["First Byte", "DCID", "Packet Number", "Payload"]
                rows.append(topRow)
                rows.append([
                    byte.binaryString,
                ])

            case .none:
                print("Unknown Header Form")
                return
        }

        outputASCIITable(rows)

        print("      \\/")

        self.inspectFirstByte()
    }
}
