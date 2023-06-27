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
    private let tlsHandler: NIOSSLHandler

    private(set) var state: QUICConnectionStateMachine
    let perspective: EndpointRole
    let version: Quic.Version

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

    //var partialCryptoBuffer: ByteBuffer = ByteBuffer()

    public init(_ remoteAddress: SocketAddress, perspective: EndpointRole, version: Version, destinationID: ConnectionID? = nil, sourceID: ConnectionID? = nil, tlsContext: NIOSSLContext) {
        self.remoteAddress = remoteAddress
        self.perspective = perspective
        self.version = version
        self.state = QUICConnectionStateMachine(role: perspective)
        self.transportParams = TransportParams.default

        // Initialize our Connection ID's
        //self.dcid = perspective == .client ? destinationID ?? ConnectionID(randomOfLength: 12) : sourceID ?? ConnectionID(randomOfLength: 0)
        self.dcid = destinationID ?? ConnectionID(randomOfLength: 12)
        self.scid = perspective == .client ? sourceID ?? ConnectionID(randomOfLength: 0) : sourceID ?? ConnectionID(randomOfLength: 0)

        // Initialize our PacketProtectorHandler
        self.packetProtectorHandler = PacketProtectorHandler(initialDCID: self.dcid, scid: self.scid, version: version, perspective: self.perspective, remoteAddress: remoteAddress)
        self.ackHandler = ACKChannelHandler()

        // Update the transport params with the original destination connection id
        self.transportParams.original_destination_connection_id = self.dcid
        self.transportParams.initial_source_connection_id = self.scid
        self.transportParams.max_idle_timeout = 30
        self.transportParams.stateless_reset_token = nil
        self.transportParams.max_udp_payload_size = 1_452
        self.transportParams.initial_max_data = 786_432
        self.transportParams.initial_max_stream_data_bidi_local = 524_288
        self.transportParams.initial_max_stream_data_bidi_remote = 524_288
        self.transportParams.initial_max_stream_data_uni = 524_288
        self.transportParams.initial_max_streams_bidi = 100
        self.transportParams.initial_max_streams_uni = 100
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
    }

    public func handlerRemoved(context: ChannelHandlerContext) {
        // We now want to drop the stored context.
        print("QUICStateHandler[\(self.perspective)]::HandlerRemoved")
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
                var packets: [any Packet] = []
                for p in packetsToEmit {
//                    var frameBuf = ByteBuffer()
//                    for frame in p.frames {
//                        frame.encode(into: &frameBuf)
//                        if let results = try self.state.processOutboundFrame(&frameBuf) {
//                            for result in results {
//                                try self.handleResult(result, packet: packet, context: context)
//                            }
//                        }
//                    }
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
