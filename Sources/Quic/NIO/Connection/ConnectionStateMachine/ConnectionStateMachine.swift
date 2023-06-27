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

struct QUICConnectionStateMachine {

    enum State {
        case idle(IdleState)
        case handshaking(HandshakingState)
        case active(ActiveState)
        case sentDisconnect
        case receivedDisconnect

        fileprivate mutating func bufferInboundPacket(_ packet: any Packet) {
            switch self {
                case .idle:
                    preconditionFailure("Cannot receive inbound data in idle state")
                case .handshaking(var state):
                    state.bufferInboundPacket(packet)
                    self = .handshaking(state)
                case .active(var state):
                    state.bufferInboundPacket(packet)
                    self = .active(state)
                case .receivedDisconnect, .sentDisconnect:
                    // No more I/O, we're done.
                    break
            }
        }

        fileprivate mutating func processInboundFrame() throws -> [StateMachineResult]? {
            switch self {
                case .idle:
                    preconditionFailure("Cannot process data in idle state")
                case .handshaking(var state):
                    var results: [StateMachineResult] = []
                    results.append(contentsOf: try state.processInboundPacket() ?? [])
                    if state.isDone {
                        print("QUICConnectionStateMachine[\(state.role)]::Handshake Done! 🤝✅")
                        self = .active(ActiveState(previous: state))
                        results.append(.installStreamMuxer)
                    } else {
                        self = .handshaking(state)
                    }

                    return results.isEmpty ? nil : results
                case .active(var state):
                    let result = try state.processInboundPacket()
                    self = .active(state)
                    return result
                case .receivedDisconnect, .sentDisconnect:
                    // No more I/O, we're done.
                    return nil
            }
        }

        fileprivate mutating func processOutboundFrame(_ buffer: inout ByteBuffer) throws -> [StateMachineResult]? {
            switch self {
                case .idle:
                    preconditionFailure("Cannot process data in idle state")
                case .handshaking(var state):
                    let result = try state.processOutboundFrame(&buffer)
                    self = .handshaking(state)
                    return result
                case .active(var state):
                    let result = try state.processOutboundFrame(&buffer)
                    self = .active(state)
                    return result
                case .receivedDisconnect, .sentDisconnect:
                    // No more I/O, we're done.
                    return nil
            }
        }
    }

    public enum Errors: Error {
        case invalidStateTransition
        case unexpectedLeftoverData
        case unexpectedFrameWhileInState(frame: any Frame, state: State)
    }

    private(set) var state: State

    public var isIdle: Bool {
        switch self.state {
            case .idle:
                return true
            default:
                return false
        }
    }

    init(role: EndpointRole) {
        self.state = .idle(IdleState(role: role))
    }

    mutating func bufferInboundPacket(_ packet: any Packet) {
        self.state.bufferInboundPacket(packet)
    }

    enum StateMachineResult {
        case updateDCID
        case emitPackets(packets: Array<(epoch: Epoch, frames: [any Frame])>)
        case forwardFrame(_ frame: any Frame)
        case dropKeys(epoch: Epoch)
        case allowBufferedFlush(epoch: Epoch)
        case installStreamMuxer
        case disconnect
        case doNothing
    }

    // This function processes the first frame in the bufferedFrames stack and issues a result
    // This function is designed to be called continuously until there is no more data to be processed (returns nil)
    mutating func processInboundFrame() throws -> [StateMachineResult]? {
        return try self.state.processInboundFrame()
    }

    mutating func processOutboundFrame(_ buffer: inout ByteBuffer) throws -> [StateMachineResult]? {
        return try self.state.processOutboundFrame(&buffer)
    }

    mutating func beginHandshake() throws {
        guard case .idle(let idleState) = self.state else {
            throw Errors.invalidStateTransition
        }

        self.state = .handshaking(HandshakingState(previous: idleState))
    }
}
