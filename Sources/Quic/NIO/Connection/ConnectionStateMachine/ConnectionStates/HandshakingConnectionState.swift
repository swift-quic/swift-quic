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
    struct HandshakingState {
        let role: EndpointRole
        private(set) var epoch: Epoch
        
        private(set) var state: HandshakeStateMachine

        var bufferedInboundPackets: [any Packet] = []
        var bufferedOutboundFrames: [any Frame] = []

        public var isDone: Bool { self.state.isDone }

        init(previous: IdleState) {
            self.role = previous.role
            self.epoch = previous.epoch
            self.state = HandshakeStateMachine(role: previous.role)
        }

        mutating func bufferInboundPacket(_ packet: any Packet) {
            self.bufferedInboundPackets.append(packet)
        }

        mutating func processInboundPacket() throws -> [StateMachineResult]? {
            guard self.bufferedInboundPackets.isEmpty == false else {
                return nil
            }
            let packet = self.bufferedInboundPackets.removeFirst()
            var results: [StateMachineResult] = []

            if packet as? ShortPacket != nil {
                guard let handshakeDone = packet.payload.first(where: { $0 as? Frames.HandshakeDone != nil }) as? Frames.HandshakeDone else {
                    throw Errors.invalidStateTransition
                }
                try self.state.processHandshakeDoneFrame(handshakeDone)
                self.bufferedInboundPackets.insert(packet, at: 0)
            } else {
                for frame in packet.payload {

                    if self.state.isDone { break }

                    if let _ = frame as? Frames.ACK {
                        // If this was acking our initial, then we should drop the initial keys
                        print("QUICConnectionStateMachine[\(self.role)]::HandshakingState::TODO::Handle ACK")
                    } else if let crypto = frame as? Frames.Crypto {
                        // read it and increment our HandshakeState...
                        let res = try self.state.processCryptoFrame(crypto)
                        results.append(contentsOf: res)

                        if self.state.state == .processedServerHello {
                            results.append(.allowBufferedFlush(epoch: .Handshake))
                            results.append(.updateDCID)
                            results.append(.dropKeys(epoch: .Initial))
                        } else if self.state.state == .processedClientFinished || self.state.state == .processedServerFinished {
                            results.append(.allowBufferedFlush(epoch: .Application))
                            if self.role == .server {
                                try self.state.processHandshakeDoneFrame(Frames.HandshakeDone())
                            }
                        }
                    } else if let done = frame as? Frames.HandshakeDone {
                        // Increment our state and complete
                        try self.state.processHandshakeDoneFrame(done)
                    } else {
                        print("QUICConnectionStateMachine[\(self.role)]::HandshakingState::ProcessInboundFrame::Unhandled Frame: \(frame)")
                        //return [.doNothing]
                    }
                }
            }

            print("QUICConnectionStateMachine[\(self.role)]::HandshakingState::Results of processing\nPacket:\(packet)\nResults:\n\t\(results.map { "\($0)" }.joined(separator: "\n\t"))")
            return results.isEmpty ? nil : results
        }

        mutating func processOutboundFrame(_ buffer: inout ByteBuffer) throws -> [StateMachineResult]? {
            let parsed = try buffer.parsePayloadIntoFrames()

            var results: [StateMachineResult] = []
            for frame in parsed.frames {
                if let crypto = frame as? Frames.Crypto {
                    // read it and increment our HandshakeState...
                    results.append(contentsOf: try self.state.processCryptoFrame(crypto))
                } else {
                    print("QUICConnectionStateMachine[\(self.role)]::HandshakingState::ProcessOutboundFrame::Unhandled Frame: \(frame)")
                }
            }

            print("QUICConnectionStateMachine[\(self.role)]::HandshakingState::Results of processing outbound frame \nFrame:\(parsed)\nResults:\n\t\(results.map { "\($0)" }.joined(separator: "\n\t"))")
            return results
        }
    }
}

extension QUICConnectionStateMachine.HandshakingState {
    struct HandshakeStateMachine: Equatable {
        public enum State: Equatable {
            case idle
            case processedClientHello
            case processedServerHello
            case processedEncryptedExtensions
            case processedCertificate
            case processedCertVerify
            case processedServerFinished
            case processedClientFinished
            case processedDone
        }

        private(set) var state: State {
            didSet { print("QUICConnectionStateMachine[\(self.role)]::HandshakingState::State Transitioned from \(oldValue) -> \(self.state)") }
        }

        private var role: EndpointRole
        private var bufferedData: ByteBuffer

        public var isDone: Bool { self.state == .processedDone }
        public var hasProcessedFinished: Bool {
            switch self.state {
                case .processedClientFinished, .processedServerFinished, .processedDone:
                    return true
                default:
                    return false
            }
        }

        public var currentEpoch: Epoch {
            switch self.state {
                case .idle, .processedClientHello:
                    return .Initial
                case .processedServerFinished, .processedClientFinished, .processedDone:
                    return .Application
                default:
                    return .Handshake
            }
        }

        public enum Errors: Error {
            case invalidStateTransition(from: State, to: State)
            case unexpectedLeftoverData
        }

        internal init(role: EndpointRole) {
            self.state = .idle
            self.role = role
            self.bufferedData = ByteBuffer()
        }

        public mutating func processCryptoFrame(_ frame: Frames.Crypto) throws -> [QUICConnectionStateMachine.StateMachineResult] {
            // Write the new crypto data into our buffer...
            self.bufferedData.writeBytes(frame.data)

            var results: [QUICConnectionStateMachine.StateMachineResult] = []
            var frames: [UInt8] = []
            var packetsToEmit: [(Epoch, [any Frame])] = []

            while self.bufferedData.readableBytes > 0 {
                switch self.state {
                    case .idle:
                        switch self.bufferedData.readTLSClientHello() {
                            case .invalidFrame:
                                throw Errors.invalidStateTransition(from: self.state, to: .processedClientHello)
                            case .needMoreData:
                                break
                            case .success(let clientHello):
                                guard self.bufferedData.readableBytes == 0 else { throw Errors.unexpectedLeftoverData }
                                self.state = .processedClientHello
                                if self.role == .client {
                                    packetsToEmit.append((epoch: .Initial, frames: [frame]))
                                } else {
                                    results.append(.forwardFrame(Frames.Crypto(offset: VarInt(integerLiteral: 0), data: clientHello)))
                                }
                        }

                    case .processedClientHello:
                        switch self.bufferedData.readTLSServerHello() {
                            case .invalidFrame:
                                throw Errors.invalidStateTransition(from: self.state, to: .processedServerHello)
                            case .needMoreData:
                                break
                            case .success(let serverHello):
                                self.state = .processedServerHello
                                if self.role == .client {
                                    results.append(.forwardFrame(Frames.Crypto(offset: VarInt(integerLiteral: 0), data: serverHello)))
                                } else {
                                    packetsToEmit.append((epoch: .Initial, frames: [Frames.Crypto(offset: VarInt(integerLiteral: 0), data: serverHello)]))
                                }
                                results.append(.allowBufferedFlush(epoch: .Handshake))
                        }

                    case .processedServerHello:
                        switch self.bufferedData.readTLSEncryptedExtensions() {
                            case .invalidFrame:
                                throw Errors.invalidStateTransition(from: self.state, to: .processedEncryptedExtensions)
                            case .needMoreData:
                                break
                            case .success(let encExt):
                                self.state = .processedEncryptedExtensions
                                if self.role == .client {
                                    //results.append(.forwardFrame(Frames.Crypto(offset: VarInt(integerLiteral: 0), data: encExt)))
                                    frames.append(contentsOf: encExt)
                                } else {
                                    frames.append(contentsOf: encExt)
                                }
                        }

                    case .processedEncryptedExtensions:
                        switch self.bufferedData.readTLSCertificate() {
                            case .invalidFrame:
                                throw Errors.invalidStateTransition(from: self.state, to: .processedCertificate)
                            case .needMoreData:
                                break
                            case .success(let cert):
                                self.state = .processedCertificate
                                if self.role == .client {
                                    //results.append(.forwardFrame(Frames.Crypto(offset: VarInt(integerLiteral: 0), data: cert)))
                                    frames.append(contentsOf: cert)
                                } else {
                                    frames.append(contentsOf: cert)
                                }
                        }

                    case .processedCertificate:
                        switch self.bufferedData.readTLSCertificateVerify() {
                            case .invalidFrame:
                                throw Errors.invalidStateTransition(from: self.state, to: .processedCertVerify)
                            case .needMoreData:
                                break
                            case .success(let certVerify):
                                self.state = .processedCertVerify
                                if self.role == .client {
                                    //results.append(.forwardFrame(Frames.Crypto(offset: VarInt(integerLiteral: 0), data: certVerify)))
                                    frames.append(contentsOf: certVerify)
                                } else {
                                    frames.append(contentsOf: certVerify)
                                }
                        }

                    case .processedCertVerify:
                        switch self.bufferedData.readTLSHandshakeFinished() {
                            case .invalidFrame:
                                throw Errors.invalidStateTransition(from: self.state, to: .processedServerFinished)
                            case .needMoreData:
                                break
                            case .success(let serverFinished):
                                self.state = .processedServerFinished
                                if self.role == .client {
                                    //results.append(.forwardFrame(Frames.Crypto(offset: VarInt(integerLiteral: 0), data: serverFinished)))
                                    frames.append(contentsOf: serverFinished)
                                } else {
                                    frames.append(contentsOf: serverFinished)
                                }
                        }

                    case .processedServerFinished:
                        switch self.bufferedData.readTLSHandshakeFinished() {
                            case .invalidFrame:
                                throw Errors.invalidStateTransition(from: self.state, to: .processedClientFinished)
                            case .needMoreData:
                                break
                            case .success(let clientFinished):
                                self.state = .processedClientFinished
                                //results.append(.dropKeys(epoch: .Handshake))
                                if self.role == .server {
                                    results.append(.forwardFrame(Frames.Crypto(offset: VarInt(integerLiteral: 0), data: clientFinished)))
                                    packetsToEmit.append((epoch: .Handshake, frames: []))
                                    packetsToEmit.append((epoch: .Application, frames: [Frames.HandshakeDone(), Frames.NewToken(token: ConnectionID(randomOfLength: 74).rawValue)]))
                                } else {
                                    packetsToEmit.append((epoch: .Handshake, frames: [frame]))
                                }
                        }

                    case .processedClientFinished:
                        print("QUICConnectionStateMachine[\(self.role)]::HandshakingState::Waiting for HandshakeDone Frame!")
                        print(self.bufferedData.readableBytesView.hexString)

                    case .processedDone:
                        print("QUICConnectionStateMachine[\(self.role)]::HandshakingState::Already Done!")
                        print(self.bufferedData.readableBytesView.hexString)
                }
            }

            if self.role == .server, !frames.isEmpty {
                packetsToEmit.append((epoch: .Handshake, frames: [Frames.Crypto(offset: VarInt(integerLiteral: 0), data: frames)]))
                frames = []
            } else if self.role == .client, !frames.isEmpty {
                results.insert(.forwardFrame(Frames.Crypto(offset: VarInt(integerLiteral: 0), data: frames)), at: 0)
                frames = []
            }

            if !packetsToEmit.isEmpty {
                results.append(.emitPackets(packets: packetsToEmit))
                packetsToEmit = []
            }

            return results
        }

        public mutating func processHandshakeDoneFrame(_ frame: Frames.HandshakeDone) throws {
            print("QUICConnectionStateMachine[\(self.role)]::HandshakingState::ProcessCryptoFrame - Current State \(self.state)")
            // We can only ever transition into processedDone from .processedClientFinished
            guard self.state == .processedClientFinished else {
                print("QUICConnectionStateMachine[\(self.role)]::HandshakingState::Error::We attempted to transition into .processedDone from an invalid state `\(self.state)`")
                throw Errors.invalidStateTransition(from: self.state, to: .processedDone)
            }
            self.state = .processedDone
        }
    }
}
