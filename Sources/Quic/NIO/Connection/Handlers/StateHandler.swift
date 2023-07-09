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

import NIO
import NIOSSL

final class QUICStateHandler: ChannelDuplexHandler, NIOSSLQuicDelegate {
    public typealias InboundIn = Packet
    public typealias InboundOut = ByteBuffer
    public typealias OutboundOut = [any Packet]
    public typealias OutboundIn = ByteBuffer

    /// Stored ChannelHandlerContext
    private var storedContext: ChannelHandlerContext!

    private let remoteAddress: SocketAddress
    private let ackHandler: ACKChannelHandler
    private let packetProtectorHandler: PacketProtectorHandler
    private let tlsContext: NIOSSLContext
    private var tlsHandler: NIOSSLHandler

    private(set) var state: QUICConnectionStateMachine
    private(set) var version: Quic.Version
    let perspective: EndpointRole

    var retiredDCIDs: [ConnectionID] = []
    var dcid: Quic.ConnectionID {
        didSet {
            print("QUICStateHandler[\(self.perspective)]::Quic State Updated::DCID \(oldValue.rawValue.hexString) -> \(self.dcid.rawValue.hexString)")
            self.retiredDCIDs.append(oldValue)
            // TODO: Do we need to update our PacketProtectorHandler
            // TODO: Do we need to update our Connection Muxer
        }
    }

    var retiredSCIDs: [ConnectionID] = []
    var scid: Quic.ConnectionID {
        didSet {
            print("QUICStateHandler[\(self.perspective)]::Quic State Updated::SCID \(oldValue.rawValue.hexString) -> \(self.scid.rawValue.hexString)")
            self.retiredSCIDs.append(oldValue)
            // TODO: Do we need to update our PacketProtectorHandler
            // TODO: Do we need to update our Connection Muxer
        }
    }

    /// Reference to our Inline Stream Muxer
    private var streamMultiplexer: QuicStreamMultiplexer?

    /// Our Transport Params
    private var transportParams: TransportParams

    private var idleTimeoutTask: Scheduled<Void>!
    private var idleTimeout: TimeAmount
    private let MINIMUM_IDLE_TIMEOUT: TimeAmount = .milliseconds(100)

    public init(_ remoteAddress: SocketAddress, perspective: EndpointRole, versions: [Version], destinationID: ConnectionID? = nil, sourceID: ConnectionID? = nil, tlsContext: NIOSSLContext, idleTimeout: TimeAmount = .seconds(3)) {
        guard !versions.isEmpty else { fatalError("Versions can't be empty") }
        self.remoteAddress = remoteAddress
        self.perspective = perspective
        self.version = versions.first!
        self.state = QUICConnectionStateMachine(role: perspective)
        self.transportParams = TransportParams.default
        self.tlsContext = tlsContext
        if idleTimeout.nanoseconds > 0 && idleTimeout < self.MINIMUM_IDLE_TIMEOUT {
            print("QUICStateHandler[\(self.perspective)]::WARNING::Non Zero IdleTimeouts less than \(self.MINIMUM_IDLE_TIMEOUT.nanoseconds / 1_000_000)ms are not supported. Adjusting timeout to a value of \(self.MINIMUM_IDLE_TIMEOUT.nanoseconds / 1_000_000)ms.")
            self.idleTimeout = self.MINIMUM_IDLE_TIMEOUT
        } else {
            self.idleTimeout = idleTimeout
        }
        // Initialize our Connection ID's
        //self.dcid = perspective == .client ? destinationID ?? ConnectionID(randomOfLength: 12) : sourceID ?? ConnectionID(randomOfLength: 0)
        self.dcid = destinationID ?? ConnectionID(randomOfLength: 12)
        self.scid = perspective == .client ? sourceID ?? ConnectionID(randomOfLength: 0) : sourceID ?? ConnectionID(randomOfLength: 0)

        // Initialize our PacketProtectorHandler
        self.packetProtectorHandler = PacketProtectorHandler(initialDCID: self.dcid, scid: self.scid, versions: versions, perspective: self.perspective, remoteAddress: remoteAddress)
        self.ackHandler = ACKChannelHandler()

        // Update the transport params with the original destination connection id
        self.transportParams.original_destination_connection_id = self.dcid
        self.transportParams.initial_source_connection_id = self.scid
        self.transportParams.max_idle_timeout = UInt64(idleTimeout.nanoseconds / 1_000_000)
        self.transportParams.stateless_reset_token = nil
        self.transportParams.max_udp_payload_size = 1_452
        self.transportParams.initial_max_data = 786_432
        self.transportParams.initial_max_stream_data_bidi_local = 524_288
        self.transportParams.initial_max_stream_data_bidi_remote = 524_288
        self.transportParams.initial_max_stream_data_uni = 524_288
        self.transportParams.initial_max_streams_bidi = 1010
        self.transportParams.initial_max_streams_uni = 1010
        //self.transportParams.ack_delay_exponent = 3
        //self.transportParams.max_ack_delay = 26
        //self.transportParams.disable_active_migration = true
        //self.transportParams.active_conn_id_limit = 4
        //self.transportParams.retry_source_connection_id = nil
        //self.transportParams.max_datagram_frame_size = nil
        //self.transportParams.preferredAddress = nil

        // SSL Context
        switch perspective {
            case .client:
                self.tlsHandler = try! NIOSSLClientHandler(context: tlsContext, serverHostname: nil)
            case .server:
                self.dcid = sourceID ?? ConnectionID(randomOfLength: 0)
                self.tlsHandler = NIOSSLServerHandler(context: tlsContext)
        }

        self.tlsHandler.setQuicDelegate(self)
    }

    deinit {
        print("QUICStateHandler[\(self.perspective)]::Deinit")
    }

    public func handlerAdded(context: ChannelHandlerContext) {
        print("QUICStateHandler[\(self.perspective)]::Added")
        self.storedContext = context

        // For the time being, if we're acting as a client, we add a datagram handler in front of our PacketProtectorHandler that handles wraping and unwrapping the bytebuffer payloads in AddressedEnvelopes
        if self.perspective == .client {
            try! context.pipeline.syncOperations.addHandler(DatagramHandler(remoteAddress: self.remoteAddress), position: .before(self))
        }

        // Install the PacketProtectorHandler and AckHandler in front of us
        try! context.pipeline.syncOperations.addHandler(self.packetProtectorHandler, position: .before(self))
        try! context.pipeline.syncOperations.addHandler(self.ackHandler, position: .before(self))
        // Install the TLSHandler behind us
        try! context.pipeline.syncOperations.addHandler(self.tlsHandler, position: .after(self))

        // Kick off our IdleTimeout timer.
        self.updateIdleTimeout()
    }

    public func handlerRemoved(context: ChannelHandlerContext) {
        // We now want to drop the stored context.
        print("QUICStateHandler[\(self.perspective)]::HandlerRemoved")
        if self.idleTimeoutTask != nil {
            self.idleTimeoutTask.cancel()
            self.idleTimeoutTask = nil
        }
        self.storedContext = nil
    }

    public func channelActive(context: ChannelHandlerContext) {
        print("QUICStateHandler[\(self.perspective)]::ChannelActive")
        // Store our context
        self.storedContext = context
        // Update our state machine
        do {
            guard self.state.isIdle else { return }
            try self.state.beginHandshake()
            context.fireChannelActive()
        } catch {
            context.fireErrorCaught(error)
            // Close?
            context.close(mode: .all, promise: nil)
            return
        }
    }

    public func channelInactive(context: ChannelHandlerContext) {
        print("QUICStateHandler[\(self.perspective)]::ChannelInactive")
        context.fireChannelInactive()
    }

    // Actions needed to be taken from reading...
    // - allow buffered message flushing
    // - drop keys
    // - send packet
    // - update connection ids
    // - install muxer
    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let packet = unwrapInboundIn(data)
        print("QUICStateHandler[\(self.perspective)]::ChannelRead") //::\(packet)")

        // Update our idle timeout
        self.updateIdleTimeout()

        do {
            self.state.bufferInboundPacket(packet)
            while let results = try self.state.processInboundFrame() {
                for result in results {
                    try self.handleResult(result, packet: packet, context: context)
                }
            }
        } catch {
            print("QUICStateHandler[\(self.perspective)]::Error::\(error)")
            context.fireErrorCaught(error)
        }
    }

    public func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        var buffer = unwrapOutboundIn(data)
        print("QUICStateHandler[\(self.perspective)]::Write::\(buffer.readableBytesView.hexString)")

        // Update our idle timeout
        self.updateIdleTimeout()

        do {
            guard let results = try self.state.processOutboundFrame(&buffer) else {
                preconditionFailure("QUICStateHandler[\(self.perspective)]::Failed to process outbound frame")
            }
            for result in results {
                try self.handleResult(result, packet: nil, context: context)
            }
        } catch {
            context.fireErrorCaught(error)
        }
    }

    internal func handleResult(_ result: QUICConnectionStateMachine.StateMachineResult, packet: (any Packet)?, context: ChannelHandlerContext) throws {
        switch result {
            case .updateDCID:
                guard let packet = packet, let long = packet.header as? LongHeader else { preconditionFailure("QUICStateHandler[\(self.perspective)]::Can't update DCID via ShortHeader") }
                self.dcid = long.sourceID

            case .dropKeys(let epoch):
                switch epoch {
                    case .Initial:
                        self.packetProtectorHandler.dropInitialKeys()
                    case .Handshake:
                        self.packetProtectorHandler.dropHandshakeKeys()
                    default:
                        preconditionFailure("QUICStateHandler[\(self.perspective)]::Can't drop application/traffic keys")
                }

            case .allowBufferedFlush(let epoch):
                switch epoch {
                    case .Initial:
                        preconditionFailure("QUICStateHandler[\(self.perspective)]::Initial data isn't buffered...")
                    case .Handshake:
                        self.packetProtectorHandler.allowHandshakeFlush()
                    case .Application:
                        self.packetProtectorHandler.allowTrafficFlush()
                }

            case .emitPackets(let packetsToEmit):
                guard !self.state.hasBegunDisconnect else { return }
                var packets: [any Packet] = []
                for p in packetsToEmit {
                    switch p.epoch {
                        case .Initial:
                            packets.append(
                                InitialPacket(
                                    header: InitialHeader(
                                        version: self.version,
                                        destinationID: self.dcid,
                                        sourceID: self.scid
                                    ),
                                    payload: p.frames
                                )
                            )
                        case .Handshake:
                            packets.append(
                                HandshakePacket(
                                    header: HandshakeHeader(
                                        version: self.version,
                                        destinationID: self.dcid,
                                        sourceID: self.scid
                                    ),
                                    payload: p.frames
                                )
                            )
                        case .Application:
                            packets.append(
                                ShortPacket(
                                    header: GenericShortHeader(
                                        firstByte: 0b01000001,
                                        id: self.dcid,
                                        packetNumber: [0x00]
                                    ),
                                    payload: p.frames
                                )
                            )
                    }
                }

                context.write(self.wrapOutboundOut(packets), promise: nil)

            case .installStreamMuxer:
                // Install our StreamMultiplexer on our pipeline to handle stream frames
                try! context.pipeline.syncOperations.addHandler(
                    QuicStreamMultiplexer(channel: context.channel, perspective: self.perspective, inboundStreamInitializer: { streamChannel in
                        streamChannel.pipeline.addHandler(StreamStateHandler())
                    }),
                    position: .after(self)
                )

            case .forwardFrame(let frame):
                print("QUICStateHandler[\(self.perspective)]::Forwarding Frame: \(frame)")
                var buf = ByteBuffer()
                frame.encode(into: &buf)
                context.fireChannelRead(self.wrapInboundOut(buf))

            case .disconnect:
                try? self.state.sentConnectionClose()
                self.tlsHandler.stopTLS(promise: nil)
                self.storedContext.pipeline.removeHandler(self.tlsHandler, promise: nil)
                self.storedContext.close(mode: .all, promise: nil)

            default:
                // Update ConnectionIDs
                // Update Tokens
                // Param Updates / Notifications
                print("QUICStateHandler[\(self.perspective)]::TODO::Implement \(result)")
        }
    }

    public func flush(context: ChannelHandlerContext) {
        print("QUICStateHandler[\(self.perspective)]::Flush::Called - Flushing")
        context.flush()
    }

    // Flush it out. This can make use of gathering writes if multiple buffers are pending
    public func channelWriteComplete(context: ChannelHandlerContext) {
        print("QUICStateHandler[\(self.perspective)]::ChannelWriteComplete::Called - Flushing")
        context.flush()
    }

    public func errorCaught(ctx: ChannelHandlerContext, error: Error) {
        print("QUICStateHandler[\(self.perspective)]::ErrorCaught: \(error)")
        ctx.close(promise: nil)
    }

    public func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if let keyUpdateInitiatedMessage = event as? ConnectionChannelEvent.KeyUpdateInitiated {
            print("QUICStateHandler[\(self.perspective)]::UserInboundEventTriggered::TODO::Got our key update initiated message!")
            print(keyUpdateInitiatedMessage)
        } else if let keyUpdateFinishedMessage = event as? ConnectionChannelEvent.KeyUpdateFinished {
            print("QUICStateHandler[\(self.perspective)]::UserInboundEventTriggered::TODO::Got our key update finished message!")
            print(keyUpdateFinishedMessage)
            self.packetProtectorHandler.dropTrafficKeysForPreviousPhase()
        } else if let versionNegotiated = event as? ConnectionChannelEvent.VersionNegotiated {
            print("QUICStateHandler[\(self.perspective)]::UserInboundEventTriggered::TODO::Handle Version Negotiated Event!")
            print(versionNegotiated)
            guard self.perspective == .client else { fatalError("QUICStateHandler[\(self.perspective)]::UserInboundEventTriggered::Server Side Connections Don't Support Version Negotiations") }
            guard versionNegotiated.version != self.version else { return }
            // Cancel our idleTimeoutTask
            self.idleTimeoutTask.cancel()
            // Update our stored Version
            self.version = versionNegotiated.version
            // Re init the State Machine
            self.state = QUICConnectionStateMachine(role: self.perspective)
            try! self.state.beginHandshake()
            // Uninstall and reinstall our TLSHandler
            let _ = context.pipeline.removeHandler(self.tlsHandler).map {
                self.tlsHandler = try! NIOSSLClientHandler(context: self.tlsContext, serverHostname: nil)
                self.tlsHandler.setQuicDelegate(self)
                return context.pipeline.addHandler(self.tlsHandler, position: .after(self))
            }.always { _ in
                print("QUICStateHandler[\(self.perspective)]::UserInboundEventTriggered::Done Reinstalling NIOSSLClientHandler")
                self.updateIdleTimeout()
            }

        } else if let versionNegotiationFailed = event as? ConnectionChannelEvent.FailedVersionNegotiation {
            print("QUICStateHandler[\(self.perspective)]::UserInboundEventTriggered::TODO::Handle Failed Version Negotiation!")
            print(versionNegotiationFailed)
            context.close(mode: .all, promise: nil)
        }
        // We consume these events. No need to pass it along.
    }

    private func updateIdleTimeout() {
        if self.idleTimeout == .zero { self.idleTimeoutTask = nil; return }
        if self.idleTimeoutTask != nil { self.idleTimeoutTask.cancel() }
        self.idleTimeoutTask = self.storedContext.eventLoop.scheduleTask(in: self.idleTimeout, {
            self.handleIdleTimeout()
        })
    }

    private func handleIdleTimeout() {
        guard self.state.hasBegunDisconnect == false else { return }
        guard self.storedContext != nil else { return }
        print("QUICStateHandler[\(self.perspective)]::We've Timed Out!")

        if case .active = self.state.state {
            let closeFrame = Frames.ConnectionClose(closeType: .quic, errorCode: VarInt(integerLiteral: 0), frameType: VarInt(integerLiteral: 0), reasonPhrase: "Idle Timeout")
            var buf = ByteBuffer()
            closeFrame.encode(into: &buf)
            let short = ShortPacket(
                header: GenericShortHeader(
                    firstByte: 0b01000001,
                    id: self.dcid,
                    packetNumber: [0x00]
                ),
                payload: [closeFrame]
            )
            self.storedContext.writeAndFlush(self.wrapOutboundOut([short]), promise: nil)
        }

        try? self.state.sentConnectionClose()

        self.tlsHandler.stopTLS(promise: nil)
        self.storedContext.pipeline.removeHandler(self.tlsHandler, promise: nil)
        self.storedContext.eventLoop.scheduleTask(in: .milliseconds(50)) {
            self.storedContext.close(mode: .all, promise: nil)
        }
    }
}

// NIOSSLQuicDelegate Protocol Conformance
extension QUICStateHandler {
    var ourParams: [UInt8] {
        print("QUICStateHandler[\(self.perspective)]::Our Quic TransportParams were accessed.\n\(self.transportParams)")
        return try! Array(self.transportParams.encode(perspective: self.perspective).readableBytesView)
    }

    var useLegacyQuicParams: Bool {
        self.version == .versionDraft29 ? true : false
    }

    func onReadSecret(epoch: UInt32, cipherSuite: UInt16, secret: [UInt8]) {
        guard let suite = try? CipherSuite(cipherSuite) else { fatalError("QUICStateHandler[\(self.perspective)]::OnReadSecret Called for unsupported CipherSuite: \(cipherSuite)") }
        switch epoch {
            case 2: // Handshake
                self.packetProtectorHandler.installHandshakeKeys(secret: secret, for: self.perspective.opposite, cipherSuite: suite)
            case 3: // Traffic / Application
                self.packetProtectorHandler.installTrafficKeys(secret: secret, for: self.perspective.opposite, cipherSuite: suite)
            default:
                fatalError("QUICStateHandler[\(self.perspective)]::OnReadSecret Called for unsupported Epoch: \(epoch) Secret: \(secret.hexString)")
        }
    }

    func onWriteSecret(epoch: UInt32, cipherSuite: UInt16, secret: [UInt8]) {
        guard let suite = try? CipherSuite(cipherSuite) else { fatalError("QUICStateHandler[\(self.perspective)]::OnWriteSecret Called for unsupported CipherSuite: \(cipherSuite)") }
        switch epoch {
            case 2: // Handshake
                self.packetProtectorHandler.installHandshakeKeys(secret: secret, for: self.perspective, cipherSuite: suite)
            case 3: // Traffic / Application
                self.packetProtectorHandler.installTrafficKeys(secret: secret, for: self.perspective, cipherSuite: suite)
            default:
                fatalError("QUICStateHandler[\(self.perspective)]::OnWriteSecret Called for unsupported Epoch: \(epoch) Secret: \(secret.hexString)")
        }
    }

    func onPeerParams(params: [UInt8]) {
        print("QUICStateHandler[\(self.perspective)]::We got our Peers Transport Params: \(params.hexString)")
        var buf = ByteBuffer(bytes: params)
        if let p = try? TransportParams.decode(&buf, perspective: self.perspective) {
            print(p)
        }
    }
}
