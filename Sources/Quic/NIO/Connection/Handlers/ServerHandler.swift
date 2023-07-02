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
import NIOCore
import NIOSSL

final class QUICServerHandler: ChannelDuplexHandler, NIOSSLQuicDelegate {
    public typealias InboundIn = Packet
    public typealias InboundOut = ByteBuffer
    public typealias OutboundOut = [any Packet]
    public typealias OutboundIn = ByteBuffer

    private let remoteAddress: SocketAddress
    private let ackHandler: ACKChannelHandler
    private let packetProtectorHandler: PacketProtectorHandler
    private let tlsHandler: NIOSSLServerHandler

    private(set) var state: QuicStateMachine.State {
        didSet { print("QUICServerHandler::State::Transitioned from \(oldValue) to \(self.state)") }
    }

    let mode: EndpointRole = .server
    let version: Quic.Version
    var didSendHandshakeDone: Bool = false

    var retiredDCIDs: [ConnectionID] = []
    var dcid: Quic.ConnectionID {
        didSet {
            print("QUICServerHandler::Quic State Updated::DCID \(oldValue.rawValue.hexString) -> \(self.dcid.rawValue.hexString)")
            self.retiredDCIDs.append(oldValue)
        }
    }

    var retiredSCIDs: [ConnectionID] = []
    var scid: Quic.ConnectionID {
        didSet {
            print("QUICServerHandler::Quic State Updated::SCID \(oldValue.rawValue.hexString) -> \(self.scid.rawValue.hexString)")
            self.retiredSCIDs.append(oldValue)
        }
    }

    private var storedContext: ChannelHandlerContext!

    var partialCryptoBuffer: ByteBuffer = ByteBuffer()

    // Quic Delegate Protocol Conformance
    private var ourTransportParams: TransportParams
    private var peerTransportParams: TransportParams?

    var ourParams: [UInt8] {
        print("Our Quic TransportParams were accessed...")
        return try! Array(self.ourTransportParams.encode(perspective: .server).readableBytesView)
    }

    var useLegacyQuicParams: Bool {
        self.version == .versionDraft29 ? true : false
    }

    func onReadSecret(epoch: UInt32, cipherSuite: UInt16, secret: [UInt8]) {
        guard let suite = try? CipherSuite(cipherSuite) else { fatalError("OnReadSecret Called for unsupported CipherSuite: \(cipherSuite)") }
        switch epoch {
            case 2:
                self.packetProtectorHandler.installHandshakeKeys(secret: secret, for: .client, cipherSuite: suite)
            case 3:
                self.packetProtectorHandler.installTrafficKeys(secret: secret, for: .client, cipherSuite: suite)
            default:
                fatalError("OnReadSecret Called for unsupported Epoch: \(epoch) Secret: \(secret.hexString)")
        }
    }

    func onWriteSecret(epoch: UInt32, cipherSuite: UInt16, secret: [UInt8]) {
        guard let suite = try? CipherSuite(cipherSuite) else { fatalError("OnWriteSecret Called for unsupported CipherSuite: \(cipherSuite)") }
        switch epoch {
            case 2:
                self.packetProtectorHandler.installHandshakeKeys(secret: secret, for: .server, cipherSuite: suite)
            case 3:
                self.packetProtectorHandler.installTrafficKeys(secret: secret, for: .server, cipherSuite: suite)
            default:
                fatalError("OnWriteSecret Called for unsupported Epoch: \(epoch) Secret: \(secret.hexString)")
        }
    }

    func onPeerParams(params: [UInt8]) {
        print("We got our Peers Transport Params: \(params.hexString)")
        var buf = ByteBuffer(bytes: params)
        self.peerTransportParams = try? TransportParams.decode(&buf, perspective: .client)
    }

    public init(_ remoteAddress: SocketAddress, version: Version, destinationID: ConnectionID, sourceID: ConnectionID? = nil, tlsContext: NIOSSLContext) {
        self.remoteAddress = remoteAddress
        self.version = version
        self.state = .idle
        self.ourTransportParams = TransportParams.default

        // Initialize our Connection ID's
        self.dcid = destinationID
        self.dcid = sourceID ?? ConnectionID(randomOfLength: 0) //destinationID ?? ConnectionID(randomOfLength: 18)
        self.scid = ConnectionID(randomOfLength: 5) //sourceID ?? ConnectionID(randomOfLength: 8)

        // Initialize our PacketProtectorHandler
        self.packetProtectorHandler = PacketProtectorHandler(initialDCID: destinationID, scid: self.scid, versions: [version], perspective: .server, remoteAddress: remoteAddress)
        self.ackHandler = ACKChannelHandler()

        // Update the transport params with the original destination connection id
        self.ourTransportParams.original_destination_connection_id = destinationID
        self.ourTransportParams.initial_source_connection_id = self.scid
        self.ourTransportParams.max_idle_timeout = 30
        self.ourTransportParams.stateless_reset_token = nil
        self.ourTransportParams.max_udp_payload_size = 1_452
        self.ourTransportParams.initial_max_data = 786_432
        self.ourTransportParams.initial_max_stream_data_bidi_local = 524_288
        self.ourTransportParams.initial_max_stream_data_bidi_remote = 524_288
        self.ourTransportParams.initial_max_stream_data_uni = 524_288
        self.ourTransportParams.initial_max_streams_bidi = 1010
        self.ourTransportParams.initial_max_streams_uni = 1010
        //self.transportParams.ack_delay_exponent = 3
        //self.transportParams.max_ack_delay = 26
        //self.transportParams.disable_active_migration = true
        //self.transportParams.active_conn_id_limit = 4
        //self.transportParams.retry_source_connection_id = nil
        //self.transportParams.max_datagram_frame_size = nil
        //self.transportParams.preferredAddress = nil

        // SSL Context
        self.tlsHandler = NIOSSLServerHandler(context: tlsContext)
        self.tlsHandler.setQuicDelegate(self)
    }

    public func handlerAdded(context: ChannelHandlerContext) {
        print("QUICServerHandler::Added")
        self.storedContext = context
        // Install the PacketProtectorHandler in front of us
        try! context.pipeline.syncOperations.addHandler(self.packetProtectorHandler, position: .before(self))
        try! context.pipeline.syncOperations.addHandler(self.ackHandler, position: .before(self))
        try! context.pipeline.syncOperations.addHandler(self.tlsHandler, position: .after(self))

        if let chan = context.channel as? QuicConnectionChannel {
            chan.activeDCIDs = [self.scid]
        }
    }

    public func handlerRemoved(context: ChannelHandlerContext) {
        // We now want to drop the stored context.
        self.storedContext = nil
    }

    public func channelActive(context: ChannelHandlerContext) {
        print("QUICServerHandler::ChannelActive")
        // Store our context
        self.storedContext = context
        // Update our state machine
        guard self.state == .idle else {
            context.fireErrorCaught(Errors.InvalidState)
            return
        }
        self.state = .handshaking(.initial)
        context.fireChannelActive()
    }

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        print("QUICServerHandler::ChannelRead")

        let packet = unwrapInboundIn(data)

        print("QUICServerHandler::Server Received Packet \(packet)")

        // If we're idle and we just received our first message, bump the state and fire a channelActive event...
        if self.state == .idle {
            self.state = .handshaking(.initial)
            context.fireChannelActive()
        }

        switch self.state {
            case .idle:
                print("QUICServerHandler::ChannelRead::Invalid State = `Idle` reading anyways")
            case .handshaking(let handshakeState):
                switch handshakeState {
                    case .initial:
                        guard let initialPacket = packet as? InitialPacket else { context.fireErrorCaught(Errors.InvalidPacket); return }
                        // Open the InitialPacket
                        // TODO: Operate on the bytebuffer directly
                        guard let cryptoFrame = initialPacket.payload.first as? Frames.Crypto else { context.fireErrorCaught(Errors.InvalidPacket); return }
                        print("CryptoFrame: \(cryptoFrame.data.hexString)")

                        //For the time being, lets strip out the ClientHello crypto frame and only send that down the pipeline...
                        // TODO: Ensure the CryptoFrame contains a ClientHello
                        guard var clientHelloBytes = ByteBuffer(bytes: cryptoFrame.data).getTLSClientHello() else { context.fireErrorCaught(Errors.InvalidPacket); return }
                        guard let clientHello = try? ClientHello(header: [], payload: &clientHelloBytes) else { context.fireErrorCaught(Errors.InvalidPacket); return }
                        print(clientHello)
                        print("Quic Params")
                        var extBuf = ByteBuffer(bytes: clientHello.extensions.first(where: { $0.type == [0x00, 0x39] || $0.type == [0xff, 0xa5] })!.value)
                        let quicParams = try! TransportParams.decode(&extBuf, perspective: .server)
                        print(quicParams)

                        var cryptoBuffer = ByteBuffer()
                        cryptoFrame.encode(into: &cryptoBuffer)
                        context.fireChannelRead(wrapInboundOut(cryptoBuffer))
                        return

                    case .firstHandshake, .secondHandshake:
                        print("QUICServerHandler::ChannelRead::TODO - Handle Handshake")
                        // At this point we're expecting a couple ACKs from the client (an Initial ACK and a Handshake ACK)
                        if let initialPacket = packet as? InitialPacket {
                            print("QUICServerHandler::ChannelRead::Processing Initial Packet")
                            // This packet should only contain an ACK...
                            guard let ack = initialPacket.payload.first as? Frames.ACK else { print("Expected an ACK, didn't get it"); return }
                            self.packetProtectorHandler.dropInitialKeys()
                        }

                        if let handshakePacket = packet as? HandshakePacket {
                            print("QUICServerHandler::ChannelRead::Processing Handshake Packet")
                            // This packet should contain at least an ACK, but also might contain the clients Handshake Finished crypto frame
                            if let cryptoFrame = handshakePacket.payload.first(where: { $0 as? Frames.Crypto != nil }) as? Frames.Crypto {
                                print("Found a Crypto Frame in our second handshake packet")
                                var cryptoBuffer = ByteBuffer()
                                cryptoFrame.encode(into: &cryptoBuffer)
                                context.fireChannelRead(wrapInboundOut(cryptoBuffer))

                                self.state = .handshaking(.done)

                                // Send an empty Handshake for Acking
                                let hsPacket = HandshakePacket(header: HandshakeHeader(version: version, destinationID: dcid, sourceID: scid), payload: [])
                                context.write(self.wrapOutboundOut([hsPacket]), promise: nil)

                                self.state = .active

                                // Install our StreamMultiplexer on our pipeline to handle stream frames
                                try! context.pipeline.syncOperations.addHandler(
                                    QuicStreamMultiplexer(channel: context.channel, perspective: .server, inboundStreamInitializer: { streamChannel in
                                        streamChannel.pipeline.addHandler(StreamStateHandler())
                                    }),
                                    position: .after(self)
                                )

                                defer { packetProtectorHandler.allowTrafficFlush() }

                                return
                            }
                        }

                        return

                    case .done:
                        print("QUICServerHandler::ChannelRead::TODO - Handle Traffic")
                }
            case .active:
                print("QUICServerHandler::ChannelRead::TODO - Handle Short / Traffic Packets")
                // This should be a stream frame
                guard let traffic = packet as? ShortPacket else { print("Expected Traffic Packet, didn't get it"); return }
                if let streamFrame = traffic.payload.first(where: { ($0 as? Frames.Stream) != nil }) as? Frames.Stream {
                    var streamBuffer = ByteBuffer()
                    streamFrame.encode(into: &streamBuffer)
                    context.fireChannelRead(self.wrapInboundOut(streamBuffer))
                }

            case .receivedDisconnect:
                print("QUICServerHandler::ChannelRead::TODO - Handle Received Disconnect")
            case .sentDisconnect:
                print("QUICServerHandler::ChannelRead::TODO - Handle Sent Disconnect")
        }
    }

    public func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        var buffer = unwrapOutboundIn(data)
        print("QUICServerHandler::Write")
        print(buffer.readableBytesView.hexString)

        switch self.state {
            case .idle:
                print("QUICServerHandler::Write::Invalid State = `Idle` writing anyways")
            case .handshaking(let handshakeState):
                switch handshakeState {
                    case .initial:
                        print("QUICServerHandler::Handling Initial")
                        // We should have 2 Crypto Frames in our buffer (the ServerHello and the first portion of our ServerHandshake (which includes the Cert and Extensions))
                        // Create the Server Initial Packet
                        guard let cryptoFrame = buffer.readCryptoFrame() else { print("Failed to read ServerHello"); return }

                        guard var serverHello = ByteBuffer(bytes: cryptoFrame.data).getTLSServerHello() else { print("QUICServerHandler::ChannelRead::Expected TLS ServerHello, didn't get it"); return }

                        // Get our chosen cipher suite
                        guard let sh = try? ServerHello(header: [], payload: &serverHello) else { print("QUICServerHandler::Failed to parse ServerHello"); return }
                        guard let cs = try? CipherSuite( sh.cipherSuite ) else { print("QUICServerHandler::Unsupported Cipher Suite `\(sh.cipherSuite)`. Abort Handshake"); return }
                        print("QUICServerHandler::ChannelRead::Updated CipherSuite \(cs)")

                        // TODO: Update our DCID and SCID
                        //self.dcid = ConnectionID(randomOfLength: 4)
                        //self.scid = ConnectionID(randomOfLength: 4)

                        let serverInitialHeader = InitialHeader(version: version, destinationID: dcid, sourceID: scid)
                        let serverInitialPacket = InitialPacket(header: serverInitialHeader, payload: [cryptoFrame])

                        // Increment our state (or should we wait for the clients ACK?)
                        self.state = .handshaking(.firstHandshake)

                        //print("Buffer State after Initial Packet")
                        //print(buffer.readableBytesView.hexString)

                        // Create the first Server Handshake Packet (consists of the TLS Encrypted Extensions, and Certifcate)
                        guard let completeServerHandshake = buffer.readCryptoFrame() else { print("Failed to read ServerHandshake"); return }
                        // Splice the completeServerHanshake into parts
                        var serverHandshakeBuffer = ByteBuffer(bytes: completeServerHandshake.data)
                        print("Total Readable Bytes for ServerHandshake: \(serverHandshakeBuffer.readableBytes)")
                        guard let encryptedExtensions = serverHandshakeBuffer.readTLSEncryptedExtensions() else { print("Failed to read encrypted extensions"); return }
                        guard let certificate = serverHandshakeBuffer.readTLSCertificate() else { print("Failed to read certificate"); return }
                        guard let certVerify = serverHandshakeBuffer.readTLSCertificateVerify() else { print("Failed to read certificate verify"); return }
                        guard let handshakeFinished = serverHandshakeBuffer.readTLSHandshakeFinished() else { print("Failed to read handshake finished"); return }
                        print("Readable Bytes After Parsing: \(buffer.readableBytes)")
                        print("Cumulative parts: \(encryptedExtensions.count + certificate.count + certVerify.count + handshakeFinished.count)")
                        // TODO: Update our DCID and SCID
                        let serverHandshakeHeader = HandshakeHeader(version: version, destinationID: dcid, sourceID: scid)
                        let serverHandshakePacket = HandshakePacket(
                            header: serverHandshakeHeader,
                            payload: [
                                Frames.Crypto(
                                    offset: VarInt(integerLiteral: 0),
                                    data: encryptedExtensions + certificate + certVerify
                                )
                            ]
                        )

                        // Coalesce these two packets into our first datagram and write it out!
                        print("Writing Coalesced Datagram")
                        context.write( wrapOutboundOut([serverInitialPacket, serverHandshakePacket]), promise: nil)

                        let serverHandshakeHeader2 = HandshakeHeader(version: version, destinationID: dcid, sourceID: scid)
                        let serverHandshakePacket2 = HandshakePacket(
                            header: serverHandshakeHeader2,
                            payload: [
                                Frames.Crypto(
                                    offset: VarInt(integerLiteral: UInt64(encryptedExtensions.count + certificate.count + certVerify.count)),
                                    data: handshakeFinished
                                )
                            ]
                        )

                        // Send the second datagram containing the Cert Verify and Finished frames..
                        context.write( wrapOutboundOut([serverHandshakePacket2]), promise: nil)

                        self.state = .handshaking(.secondHandshake)

                        self.packetProtectorHandler.allowHandshakeFlush()
                        self.packetProtectorHandler.allowTrafficFlush()

                        return

                    case .firstHandshake, .secondHandshake:
                        print("QUICServerHandler::Write::TODO:Handle Handshake")

                    case .done:
                        print("QUICServerHandler::Write::TODO:Handle Traffic")
                }
            case .active:
                print("QUICServerHandler::Write::TODO:Handle Short / Traffic Packets")
                if !self.didSendHandshakeDone {
                    self.didSendHandshakeDone = true
                    let donePacket = ShortPacket(
                        header: GenericShortHeader(firstByte: 0b01000001, id: self.dcid, packetNumber: []),
                        payload: [Frames.HandshakeDone(), Frames.NewToken(token: ConnectionID(randomOfLength: 74).rawValue)]
                    )
                    // Echo the stream frame
                    context.write(self.wrapOutboundOut([donePacket]), promise: nil)
                }

                if let streamFrame = buffer.readStreamFrame() {
                    let packet = ShortPacket(
                        header: GenericShortHeader(firstByte: 0b01000001, id: self.dcid, packetNumber: []),
                        payload: [streamFrame]
                    )
                    // Send along the stream frame
                    context.write(self.wrapOutboundOut([packet]), promise: nil)
                }

            case .receivedDisconnect:
                print("QUICServerHandler::Write::TODO:Handle Received Disconnect")
            case .sentDisconnect:
                print("QUICServerHandler::Write::TODO:Handle Sent Disconnect")
        }
    }

    public func flush(context: ChannelHandlerContext) {
        print("QUICServerHandler::Flush::Called - Flushing")
        context.flush()
    }

    // Flush it out. This can make use of gathering writes if multiple buffers are pending
    public func channelWriteComplete(context: ChannelHandlerContext) {
        print("QUICServerHandler::ChannelWriteComplete::Called - Flushing")
        context.flush()
    }

    public func errorCaught(ctx: ChannelHandlerContext, error: Error) {
        print("QUICServerHandler::ErrorCaught: \(error)")
        ctx.close(promise: nil)
    }

    public func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if let keyUpdateInitiatedMessage = event as? ConnectionChannelEvent.KeyUpdateInitiated {
            print("QUICServerHandler::UserInboundEventTriggered::TODO::Got our key update initiated message!")
            print(keyUpdateInitiatedMessage)
        } else if let keyUpdateFinishedMessage = event as? ConnectionChannelEvent.KeyUpdateFinished {
            print("QUICServerHandler::UserInboundEventTriggered::TODO::Got our key update finished message!")
            print(keyUpdateFinishedMessage)
            self.packetProtectorHandler.dropTrafficKeysForPreviousPhase()
        }
        // We consume this event. No need to pass it along.
    }
}
