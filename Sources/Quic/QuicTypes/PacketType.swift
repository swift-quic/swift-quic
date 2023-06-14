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

/// `PacketType` is a loose wrapper around the various QUIC Packet Types
/// - Note: This is kind of redundant, consider removing this in the future.
public enum PacketType {
    /// Initial packet.
    case Initial

    /// Retry packet.
    case Retry

    /// Handshake packet.
    case Handshake

    /// 0-RTT packet.
    case ZeroRTT

    /// Version negotiation packet.
    case VersionNegotiation

    /// 1-RTT short header packet.
    case Short

    /// Given an `Epoch`, instantiate a `PacketType` case
    public init(_ epoch: Epoch) {
        switch epoch {
            case .Initial:
                self = .Initial

            case .Handshake:
                self = .Handshake

            case .Application:
                self = .Short
        }
    }

    /// Given a Header byte, instantiate a `PacketType` case
    public init?(_ byte: UInt8) {
        switch Quic.HeaderForm(rawValue: byte & Quic.HeaderForm.mask) {
            case .long:
                switch Quic.LongPacketType(rawValue: byte & Quic.LongPacketType.mask) {
                    case .initial:
                        self = .Initial
                    case .handshake:
                        self = .Handshake
                    case .retry:
                        self = .Retry
                    case .zeroRTT:
                        self = .ZeroRTT
                    case .none:
                        return nil
                }
            case .short:
                self = .Short
            case .none:
                return nil
        }
    }

    init?(_ packet: any Packet) {
        if packet as? InitialPacket != nil {
            self = .Initial
        } else if packet as? HandshakePacket != nil {
            self = .Handshake
        } else if packet as? ShortPacket != nil {
            self = .Short
        } else if packet as? VersionNegotiationPacket != nil {
            self = .VersionNegotiation
        } else {
            return nil
        }
    }

    /// Converts a `PacketType` to it's associated `Epoch`
    func toEpoch() throws -> Epoch {
        switch self {
            case .Initial:
                return .Initial
            case .ZeroRTT:
                return .Application
            case .Handshake:
                return .Handshake
            case .Short:
                return .Application
            default:
                throw Errors.NoEpochAssociatedWithPacketType
        }
    }

    /// Convenience check to test if a `PacketType` contains a Long Header.
    public var isLongHeader: Bool {
        switch self {
            case .Short: return false
            default: return true
        }
    }
}
