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

extension QUICConnectionStateMachine {
    struct ActiveState {
        let role: EndpointRole
        let epoch: Epoch
        
        var bufferedInboundPackets: [any Packet] = []

        init(previous: HandshakingState) {
            guard previous.isDone else { preconditionFailure("Can't transition from Handshaking to Active via an unfinished HandshakingState") }
            self.role = previous.role
            self.epoch = previous.epoch
            self.bufferedInboundPackets = previous.bufferedInboundPackets
        }

        mutating func bufferInboundPacket(_ packet: any Packet) {
            self.bufferedInboundPackets.append(packet)
        }

        mutating func processInboundPacket() throws -> [StateMachineResult]? {
            guard !self.bufferedInboundPackets.isEmpty else { return nil }
            let packet = self.bufferedInboundPackets.removeFirst()

            var results: [StateMachineResult] = []
            for frame in packet.payload {
                if let result = try self.processInboundFrame(frame, perspective: self.role) {
                    results.append(contentsOf: result)
                }
            }

            if !results.contains(where: { if case .emitPackets = $0 { return true } else { return false } }) {
                results.append(.emitPackets(packets: [(epoch: .Application, frames: [])]))
            }

            return results.isEmpty ? nil : results
        }

        mutating func processOutboundFrame(_ buffer: inout ByteBuffer) throws -> [StateMachineResult]? {
            let frames = try buffer.parsePayloadIntoFrames()
            var results: [StateMachineResult] = []
            for frame in frames.frames {
                try results.append(contentsOf: self.processOutboundFrame(frame, perspective: self.role) ?? [])
            }

            results.append(.emitPackets(packets: [(epoch: .Application, frames: frames.frames)]))

            return results
        }
    }
}

extension QUICConnectionStateMachine.ActiveState {
    internal func processInboundFrame(_ frame: any Frame, perspective: EndpointRole) throws -> [QUICConnectionStateMachine.StateMachineResult]? {
        switch frame.type {
            case Frames.Padding.type:
                return []
            case Frames.Ping.type:
                print("QUICStateHandler[\(perspective)]::ProcessFrame::Handle Ping")
                // TODO: Respond to PING
                return [.emitPackets(packets: [(epoch: .Application, frames: [Frames.Ping()])])]

            case 0x02...0x03: //Frames.ACK
                print("QUICStateHandler[\(perspective)]::ProcessFrame::Handle ACK")
                // We can neglect / discard these as they've already been processed by our ack handler

            case Frames.ResetStream.type:
                print("QUICStateHandler[\(perspective)]::ProcessFrame::Handle ResetStream")

            case Frames.StopSending.type:
                print("QUICStateHandler[\(perspective)]::ProcessFrame::Handle StopSending")

            case Frames.Crypto.type:
                print("QUICStateHandler[\(perspective)]::ProcessFrame::Handle Crypto")
            // Pass the Crypto Frame along the pipeline (the NIOSSLHandler will pick it up and consume it)
            //return [.forwardFrame(frame)]

            case Frames.NewToken.type:
                print("QUICStateHandler[\(perspective)]::ProcessFrame::Handle NewToken")

            case 0x08...0x0f: //Frames.Stream
                print("QUICStateHandler[\(perspective)]::ProcessFrame::Handle Stream Frame")
                return [.forwardFrame(frame)]

            case Frames.MaxData.type:
                print("QUICStateHandler[\(perspective)]::ProcessFrame::Handle Max Data")

            case Frames.MaxStreamData.type:
                print("QUICStateHandler[\(perspective)]::ProcessFrame::Handle Max Stream Data")

            case 0x12...0x13: //Frames.MaxStreams
                print("QUICStateHandler[\(perspective)]::ProcessFrame::Handle Max Streams")

            case Frames.DataBlocked.type:
                print("QUICStateHandler[\(perspective)]::ProcessFrame::Handle Data Blocked")

            case Frames.StreamDataBlocked.type:
                print("QUICStateHandler[\(perspective)]::ProcessFrame::Handle Stream Data Blocked")

            case 0x16...0x17: //Frames.StreamsBlocked
                print("QUICStateHandler[\(perspective)]::ProcessFrame::Handle Streams Blocked")

            case Frames.NewConnectionID.type:
                print("QUICStateHandler[\(perspective)]::ProcessFrame::Handle New ConnectionID")

            case Frames.RetireConnectionID.type:
                print("QUICStateHandler[\(perspective)]::ProcessFrame::Handle Retire Connection ID")

            case Frames.PathChallenge.type:
                print("QUICStateHandler[\(perspective)]::ProcessFrame::Handle Path Challenge")

            case Frames.PathResponse.type:
                print("QUICStateHandler[\(perspective)]::ProcessFrame::Handle Path Response")

            case 0x1c...0x1d: //Frames.ConnectionClose
                print("QUICStateHandler[\(perspective)]::ProcessFrame::Handle Connection Close")

            case Frames.HandshakeDone.type:
                print("QUICStateHandler[\(perspective)]::ProcessFrame::Handle Handshake Done")

            default:
                fatalError("QUICStateHandler[\(perspective)]::Unknown Frame: \(frame)")
        }
        return nil
    }

    internal func processOutboundFrame(_ frame: any Frame, perspective: EndpointRole) throws -> [QUICConnectionStateMachine.StateMachineResult]? {
        switch frame.type {
            case Frames.Padding.type:
                return []
            case Frames.Ping.type:
                print("QUICStateHandler[\(perspective)]::ProcessFrame::Handle Ping")
            // TODO: Respond to PING
            //return [.emitPackets(packets: [(epoch: .Application, frames: [Frames.Ping()])])]

            case 0x02...0x03: //Frames.ACK
                print("QUICStateHandler[\(perspective)]::ProcessFrame::Handle ACK")
            // We can neglect / discard these as they've already been processed by our ack handler

            case Frames.ResetStream.type:
                print("QUICStateHandler[\(perspective)]::ProcessFrame::Handle ResetStream")

            case Frames.StopSending.type:
                print("QUICStateHandler[\(perspective)]::ProcessFrame::Handle StopSending")

            case Frames.Crypto.type:
                print("QUICStateHandler[\(perspective)]::ProcessFrame::Handle Crypto")
            // Pass the Crypto Frame along the pipeline (the NIOSSLHandler will pick it up and consume it)
            //return [.forwardFrame(frame)]

            case Frames.NewToken.type:
                print("QUICStateHandler[\(perspective)]::ProcessFrame::Handle NewToken")

            case 0x08...0x0f: //Frames.Stream
                print("QUICStateHandler[\(perspective)]::ProcessFrame::Handle Stream Frame")
            //return [.forwardFrame(frame)]

            case Frames.MaxData.type:
                print("QUICStateHandler[\(perspective)]::ProcessFrame::Handle Max Data")

            case Frames.MaxStreamData.type:
                print("QUICStateHandler[\(perspective)]::ProcessFrame::Handle Max Stream Data")

            case 0x12...0x13: //Frames.MaxStreams
                print("QUICStateHandler[\(perspective)]::ProcessFrame::Handle Max Streams")

            case Frames.DataBlocked.type:
                print("QUICStateHandler[\(perspective)]::ProcessFrame::Handle Data Blocked")

            case Frames.StreamDataBlocked.type:
                print("QUICStateHandler[\(perspective)]::ProcessFrame::Handle Stream Data Blocked")

            case 0x16...0x17: //Frames.StreamsBlocked
                print("QUICStateHandler[\(perspective)]::ProcessFrame::Handle Streams Blocked")

            case Frames.NewConnectionID.type:
                print("QUICStateHandler[\(perspective)]::ProcessFrame::Handle New ConnectionID")

            case Frames.RetireConnectionID.type:
                print("QUICStateHandler[\(perspective)]::ProcessFrame::Handle Retire Connection ID")

            case Frames.PathChallenge.type:
                print("QUICStateHandler[\(perspective)]::ProcessFrame::Handle Path Challenge")

            case Frames.PathResponse.type:
                print("QUICStateHandler[\(perspective)]::ProcessFrame::Handle Path Response")

            case 0x1c...0x1d: //Frames.ConnectionClose
                print("QUICStateHandler[\(perspective)]::ProcessFrame::Handle Connection Close")

            case Frames.HandshakeDone.type:
                print("QUICStateHandler[\(perspective)]::ProcessFrame::Handle Handshake Done")

            default:
                fatalError("QUICStateHandler[\(perspective)]::Unknown Frame: \(frame)")
        }
        return nil
    }
}
