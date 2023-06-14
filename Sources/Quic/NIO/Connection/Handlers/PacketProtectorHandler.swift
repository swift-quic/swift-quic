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

final class PacketProtectorHandler: ChannelDuplexHandler {
    public typealias InboundIn = AddressedEnvelope<ByteBuffer>
    public typealias InboundOut = Packet
    public typealias OutboundOut = AddressedEnvelope<ByteBuffer>
    public typealias OutboundIn = [any Packet] // This is an array, so we can explicitly coallese packets within a datagram

    private let perspective: EndpointRole
    private let scid: ConnectionID

    internal var initialKeys: PacketProtector
    internal var handshakeKeys: PacketProtector
    internal var trafficKeys: PacketProtector
    private var storedContext: ChannelHandlerContext!

    private let remoteAddress: SocketAddress

    private var canFlushHandshakeBuffer: Bool = false {
        didSet { if self.canFlushHandshakeBuffer && self.encryptedHandshakeBuffer.readableBytes > 0 && self.handshakeKeys.opener != nil { self.decryptAndFlushHandshakeBuffer() } }
    }

    internal var encryptedHandshakeBuffer: ByteBuffer = ByteBuffer()

    private var canFlushTrafficBuffer: Bool = false {
        didSet { if self.canFlushTrafficBuffer && self.encryptedTrafficBuffer.readableBytes > 0 && self.trafficKeys.opener != nil { self.decryptAndFlushTrafficBuffer() } }
    }

    internal var encryptedTrafficBuffer: ByteBuffer = ByteBuffer()

    init(initialDCID dcid: ConnectionID, scid: ConnectionID, version: Version, perspective: EndpointRole, remoteAddress: SocketAddress) {
        self.perspective = perspective
        self.scid = scid
        self.remoteAddress = remoteAddress
        // Generate Initial Key Sets
        self.initialKeys = try! version.newInitialAEAD(connectionID: dcid, perspective: perspective)
        self.handshakeKeys = PacketProtector(epoch: .Handshake, version: version)
        self.trafficKeys = PacketProtector(epoch: .Handshake, version: version)
    }

    public func handlerAdded(context: ChannelHandlerContext) {
        self.storedContext = context
    }

    public func handlerRemoved(context: ChannelHandlerContext) {
        self.storedContext = nil
    }

    deinit {
        self.storedContext = nil
    }

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let envelope = self.unwrapInboundIn(data)

        print("PacketProtectorHandler::ChannelRead::Envelope: \(envelope)")
        //print(envelope.data.readableBytesView.hexString)

        // TODO: We should be comparing DCID here, or we just trust the Muxer to do it's job and operate on ByteBuffers instead of AddressedEnvelopes.
        //guard envelope.remoteAddress == context.channel.remoteAddress! else {
        //    print("QUICClientHandler::ChannelRead::Remote Address Mismatch \(envelope.remoteAddress) != \(context.channel.remoteAddress!)")
        //    return
        //}

        var buffer = envelope.data

        // Read the packets
        var packetsToProcess: [any Packet] = []
        packetLoop: while buffer.readableBytes > 0 {
            // Determine the Packet Type
            guard let firstByte = buffer.getBytes(at: buffer.readerIndex, length: 1)?.first else { break }
            // Decrypt the Packet (or buffer it if we don't have the keys yet)
            var packet: (any Packet)?
            switch PacketType(firstByte) {
                case .Initial:
                    guard let p = buffer.readEncryptedQuicInitialPacket(using: initialKeys) else {
                        fatalError("PacketProtectorHandler::ChannelRead::Failed to decrypt initial packet")
                    }
                    packet = p
                case .Handshake:
                    guard self.handshakeKeys.opener != nil else {
                        print("PacketProtectorHandler::ChannelRead::Handshake Keys Not Available Yet! Buffering Handshake Packet")
                        guard let (_, totalPacketLength) = try? buffer.getLongHeaderPacketNumberOffsetAndTotalLength() else {
                            fatalError("PacketProtectorHandler::ChannelRead::Failed to fetch PNO and Length for Encrypted Handshake Packet")
                        }
                        guard var encryptedPacket = buffer.readSlice(length: totalPacketLength) else {
                            fatalError("PacketProtectorHandler::ChannelRead::Failed to fetch PNO and Length for Encrypted Handshake Packet")
                        }
                        self.encryptedHandshakeBuffer.writeBuffer(&encryptedPacket)
                        break
                    }
                    guard let p = buffer.readEncryptedQuicHandshakePacket(using: handshakeKeys) else {
                        fatalError("PacketProtectorHandler::ChannelRead::Failed to decrypt handshake packet")
                    }
                    packet = p
                case .Short:
                    guard self.trafficKeys.opener != nil else {
                        print("PacketProtectorHandler::ChannelRead::Traffic Keys Not Available Yet! Buffering Traffic Packet")
                        self.encryptedTrafficBuffer.writeBuffer(&buffer)
                        break
                    }
                    guard let p = buffer.readEncryptedQuicTrafficPacket(dcid: scid, using: trafficKeys) else {
                        fatalError("PacketProtectorHandler::ChannelRead::Failed to decrypt traffic packet")
                    }
                    packet = p

                default:
                    fatalError("PacketProtectorHandler::ChannelRead::TODO:Handle Packet Type: \(PacketType(firstByte)!)")
            }
            if let packet {
                packetsToProcess.append(packet)
            }
        }

        // Send each packet along the pipeline
        print("PacketProtectorHandler::ChannelRead::We have \(packetsToProcess.count) Packets that need to be processed...")
        packetsToProcess.forEach { packet in
            context.fireChannelRead(self.wrapInboundOut(packet))
        }

        // Notify that we finished reading
        //context.fireChannelReadComplete()
    }

    public func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        var packets = self.unwrapOutboundIn(data)

        // Check for the inclusion of InitialPackets and pad the datagram if so!
        self.padDatagramIfNecessary(packets: &packets)

        var datagramPayload = ByteBuffer()

        packets.forEach { packet in
            print("PacketProtectorHandler::Write::Encrypting Packet")
            print("PacketProtectorHandler::Write::\(packet)")

            do {
                let enc: (protectedHeader: [UInt8], encryptedPayload: [UInt8])
                switch PacketType(packet.header.firstByte) {
                    case .Initial:
                        enc = try (packet as! InitialPacket).seal(using: initialKeys)
                    case .Handshake:
                        enc = try (packet as! HandshakePacket).seal(using: handshakeKeys)
                    case .Short:
                        enc = try (packet as! ShortPacket).seal(using: trafficKeys)
                    default:
                        context.fireErrorCaught(Errors.InvalidPacket)
                        fatalError("PacketProtectorhandler::Write::Handle Packet Type \(PacketType(packet.header.firstByte)!)")
                }
                datagramPayload.writeBytes(enc.protectedHeader)
                datagramPayload.writeBytes(enc.encryptedPayload)
            } catch {
                fatalError("Failed to encrypt packet `\(error)`")
            }
        }

        let datagram = AddressedEnvelope(remoteAddress: remoteAddress, data: datagramPayload)
        print("PacketProtectorHandler::Write::Sending Datagram")
        print("PacketProtectorHandler::Write::\(datagram.data.readableBytesView.hexString)")
        context.writeAndFlush(self.wrapOutboundOut(datagram), promise: promise)
    }

    // This function should be called by our StateHandler
    public func installHandshakeKeys(secret: [UInt8], for mode: EndpointRole, cipherSuite: CipherSuite = .AESGCM128_SHA256) {
        // Given the handshake secret generate the necessary keys for Handshake Packet Protection
        print("PacketProtectorHandler::InstallHandshakeKeys:: 🔐 Generating and Installing \(mode) Key Set for Handshake Packet Protection 🔐")
        print("PacketProtectorHandler::InstallHandshakeKeys::Using Secret: \(secret.hexString)")

        // Install the keys
        do {
            try self.handshakeKeys.installKeySet(suite: cipherSuite, secret: secret, for: mode, ourPerspective: self.perspective)
            if self.canFlushHandshakeBuffer && mode != self.perspective {
                print("PacketProtectorHandler::InstallHandshakeKeys::Attempting to Read Buffered Handshake Packets...")
                self.decryptAndFlushHandshakeBuffer()
            }
        } catch {
            self.storedContext.fireErrorCaught(error)
        }
    }

    // This function should be called by our StateHandler
    public func installTrafficKeys(secret: [UInt8], for mode: EndpointRole, cipherSuite: CipherSuite = .ChaChaPoly_SHA256) {
        // Given the traffic secret generate the necessary keys for Traffic Packet Protection
        print("PacketProtectorHandler::InstallTrafficKeys:: 🔐 Generating and Installing \(mode) Key Set for Traffic Packet Protection 🔐")
        print("PacketProtectorHandler::InstallTrafficKeys::Using Secret: \(secret.hexString)")

        // Install the keys
        do {
            try self.trafficKeys.installKeySet(suite: cipherSuite, secret: secret, for: mode, ourPerspective: self.perspective)
            if self.canFlushTrafficBuffer && mode != self.perspective {
                print("PacketProtectorHandler::InstallTrafficKeys::Attempting to Read Buffered Traffic Packets...")
                self.decryptAndFlushTrafficBuffer()
            }
        } catch {
            self.storedContext.fireErrorCaught(error)
        }
    }

    public func allowHandshakeFlush() {
        guard self.canFlushHandshakeBuffer == false else { return }
        self.canFlushHandshakeBuffer = true
    }

    public func allowTrafficFlush() {
        guard self.canFlushTrafficBuffer == false else { return }
        self.canFlushTrafficBuffer = true
    }

    public func dropInitialKeys() {
        self.initialKeys.dropKeys()
    }

    public func dropHandshakeKeys() {
        self.handshakeKeys.dropKeys()
    }

    private func decryptAndFlushHandshakeBuffer() {
        print("PacketProtectorHandler::DecryptAndFlushHandshakeBuffer")
        while self.encryptedHandshakeBuffer.readableBytes > 0 {
            guard let packet = encryptedHandshakeBuffer.readEncryptedQuicHandshakePacket(using: self.handshakeKeys) else {
                print("PacketProtectorHandler::DecryptAndFlushHandshakeBuffer::Failed to Decrypt Buffered Handshake Packet")
                self.storedContext.fireErrorCaught(Errors.InvalidPacket)
                break
            }
            print("PacketProtectorHandler::DecryptAndFlushHandshakeBuffer::Flushing Buffer Handshake Packet")
            self.storedContext.fireChannelRead(self.wrapInboundOut(packet))
        }
    }

    private func decryptAndFlushTrafficBuffer() {
        print("PacketProtectorHandler::DecryptAndFlushTrafficBuffer")
        while self.encryptedTrafficBuffer.readableBytes > 0 {
            guard let packet = encryptedTrafficBuffer.readEncryptedQuicTrafficPacket(dcid: self.scid, using: self.trafficKeys) else {
                print("PacketProtectorHandler::DecryptAndFlushTrafficBuffer::Failed to Decrypt Buffered Traffic Packet")
                self.storedContext.fireErrorCaught(Errors.InvalidPacket)
                break
            }
            print("PacketProtectorHandler::DecryptAndFlushTrafficBuffer::Flushing Buffer Traffic Packet")
            self.storedContext.fireChannelRead(self.wrapInboundOut(packet))
        }
    }

    private func padDatagramIfNecessary(packets: inout [any Packet]) {
        // If the outbound datagram includes an InitialPacket, it needs to be padded to at least 1200 bytes
        if let initialPacketIndex = packets.firstIndex(where: { $0 as? InitialPacket != nil }) {
            guard var initialPacket = packets[initialPacketIndex] as? InitialPacket else { fatalError("InitialPacket turned out to not be an initial packet...") }
            // Get the total estimated bytes for all the packets
            var estimatedLength = 0
            for packet in packets {
                estimatedLength += packet.headerBytes.count + packet.serializedPayload.count + 16
            }

            // Construct our Padding Frame of appropriate length
            let padding = Frames.Padding(length: 1248 - estimatedLength)

            // Inject the padding into our initial packet so it gets encrypted
            initialPacket.payload.insert(padding, at: 0)
            print("PacketProtectorHandler::PadDatagramIfNecessary::Adding \(1248 - estimatedLength) bytes of padding to our initial packet")

            // Update the packet in our packet array
            packets[initialPacketIndex] = initialPacket
        }

        // TODO: Check if short packet is long enough...
    }
}

/// The only difference between this Handler and PacketProtectorHandler is that it opperates on ByteBuffers instead of AddressedEnvelopes
final class PacketProtectorHandler2: ChannelDuplexHandler {
    public typealias InboundIn = ByteBuffer
    public typealias InboundOut = Packet
    public typealias OutboundOut = ByteBuffer
    public typealias OutboundIn = [any Packet] // This is an array, so we can explicitly coallese packets within a datagram

    private let perspective: EndpointRole
    private let scid: ConnectionID

    internal var initialKeys: PacketProtector
    internal var handshakeKeys: PacketProtector
    internal var trafficKeys: PacketProtector
    private var storedContext: ChannelHandlerContext!

    private let remoteAddress: SocketAddress

    private var canFlushHandshakeBuffer: Bool = false {
        didSet { if self.canFlushHandshakeBuffer && self.encryptedHandshakeBuffer.readableBytes > 0 && self.handshakeKeys.opener != nil { self.decryptAndFlushHandshakeBuffer() } }
    }

    internal var encryptedHandshakeBuffer: ByteBuffer = ByteBuffer()

    private var canFlushTrafficBuffer: Bool = false {
        didSet { if self.canFlushTrafficBuffer && self.encryptedTrafficBuffer.readableBytes > 0 && self.trafficKeys.opener != nil { self.decryptAndFlushTrafficBuffer() } }
    }

    internal var encryptedTrafficBuffer: ByteBuffer = ByteBuffer()

    init(initialDCID dcid: ConnectionID, scid: ConnectionID, version: Version, perspective: EndpointRole, remoteAddress: SocketAddress) {
        self.perspective = perspective
        self.scid = scid
        self.remoteAddress = remoteAddress
        // Generate Initial Key Sets
        self.initialKeys = try! version.newInitialAEAD(connectionID: dcid, perspective: perspective)
        self.handshakeKeys = PacketProtector(epoch: .Handshake, version: version)
        self.trafficKeys = PacketProtector(epoch: .Handshake, version: version)
    }

    public func handlerAdded(context: ChannelHandlerContext) {
        self.storedContext = context
    }

    public func handlerRemoved(context: ChannelHandlerContext) {
        self.storedContext = nil
    }

    deinit {
        self.storedContext = nil
    }

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buffer = self.unwrapInboundIn(data)

        print("PacketProtectorHandler::ChannelRead::Envelope: \(buffer.readableBytesView.hexString)")

        // Read the packets
        var packetsToProcess: [any Packet] = []
        packetLoop: while buffer.readableBytes > 0 {
            // Determine the Packet Type
            guard let firstByte = buffer.getBytes(at: buffer.readerIndex, length: 1)?.first else { break }
            // Decrypt the Packet (or buffer it if we don't have the keys yet)
            var packet: (any Packet)?
            switch PacketType(firstByte) {
                case .Initial:
                    guard let p = buffer.readEncryptedQuicInitialPacket(using: initialKeys) else {
                        fatalError("PacketProtectorHandler::ChannelRead::Failed to decrypt initial packet")
                    }
                    packet = p
                case .Handshake:
                    guard self.handshakeKeys.opener != nil else {
                        print("PacketProtectorHandler::ChannelRead::Handshake Keys Not Available Yet! Buffering Handshake Packet")
                        guard let (_, totalPacketLength) = try? buffer.getLongHeaderPacketNumberOffsetAndTotalLength() else {
                            fatalError("PacketProtectorHandler::ChannelRead::Failed to fetch PNO and Length for Encrypted Handshake Packet")
                        }
                        guard var encryptedPacket = buffer.readSlice(length: totalPacketLength) else {
                            fatalError("PacketProtectorHandler::ChannelRead::Failed to fetch PNO and Length for Encrypted Handshake Packet")
                        }
                        self.encryptedHandshakeBuffer.writeBuffer(&encryptedPacket)
                        break
                    }
                    guard let p = buffer.readEncryptedQuicHandshakePacket(using: handshakeKeys) else {
                        fatalError("PacketProtectorHandler::ChannelRead::Failed to decrypt handshake packet")
                    }
                    packet = p
                case .Short:
                    guard self.trafficKeys.opener != nil else {
                        print("PacketProtectorHandler::ChannelRead::Traffic Keys Not Available Yet! Buffering Traffic Packet")
                        self.encryptedTrafficBuffer.writeBuffer(&buffer)
                        break
                    }
                    guard let p = buffer.readEncryptedQuicTrafficPacket(dcid: scid, using: trafficKeys) else {
                        fatalError("PacketProtectorHandler::ChannelRead::Failed to decrypt traffic packet")
                    }
                    packet = p

                default:
                    fatalError("PacketProtectorHandler::ChannelRead::TODO:Handle Packet Type: \(PacketType(firstByte)!)")
            }
            if let packet {
                packetsToProcess.append(packet)
            }
        }

        // Send each packet along the pipeline
        print("PacketProtectorHandler::ChannelRead::We have \(packetsToProcess.count) Packets that need to be processed...")
        packetsToProcess.forEach { packet in
            print("PacketProtectorHandler::ChannelRead::Packet: \(packet.header)")
            print("PacketProtectorHandler::ChannelRead::Payload: \(packet.serializedPayload.hexString)")
            context.fireChannelRead(self.wrapInboundOut(packet))
        }

        // Notify that we finished reading
        //context.fireChannelReadComplete()
    }

    public func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        var packets = self.unwrapOutboundIn(data)

        // Check for the inclusion of InitialPackets and pad the datagram if so!
        self.padDatagramIfNecessary(packets: &packets)

        var datagramPayload = ByteBuffer()

        for packet in packets {
            guard !packet.payload.isEmpty else { print("PacketProtectorHandler::Write::Dropping Empty Outbound Packet"); continue }

            print("PacketProtectorHandler::Write::Encrypting Packet")
            print("PacketProtectorHandler::Write::\(packet)")

            do {
                let enc: (protectedHeader: [UInt8], encryptedPayload: [UInt8])
                switch PacketType(packet.header.firstByte) {
                    case .Initial:
                        enc = try (packet as! InitialPacket).seal(using: self.initialKeys)
                    case .Handshake:
                        enc = try (packet as! HandshakePacket).seal(using: self.handshakeKeys)
                    case .Short:
                        enc = try (packet as! ShortPacket).seal(using: self.trafficKeys)
                    default:
                        context.fireErrorCaught(Errors.InvalidPacket)
                        fatalError("PacketProtectorhandler::Write::Handle Packet Type \(PacketType(packet.header.firstByte)!)")
                }
                datagramPayload.writeBytes(enc.protectedHeader)
                datagramPayload.writeBytes(enc.encryptedPayload)
            } catch {
                fatalError("Failed to encrypt packet `\(error)`")
            }
        }

        //let datagram = AddressedEnvelope(remoteAddress: remoteAddress, data: datagramPayload)
        print("PacketProtectorHandler::Write::Sending Datagram")
        print("PacketProtectorHandler::Write::\(datagramPayload.readableBytesView.hexString)")
        context.writeAndFlush(self.wrapOutboundOut(datagramPayload), promise: promise)
    }

    // This function should be called by our StateHandler
    public func installHandshakeKeys(secret: [UInt8], for mode: EndpointRole, cipherSuite: CipherSuite = .AESGCM128_SHA256) {
        // Given the handshake secret generate the necessary keys for Handshake Packet Protection
        print("PacketProtectorHandler::InstallHandshakeKeys:: 🔐 Generating and Installing \(mode) Key Set for Handshake Packet Protection 🔐")
        print("PacketProtectorHandler::InstallHandshakeKeys::Using Secret: \(secret.hexString)")

        // Install the keys
        do {
            try self.handshakeKeys.installKeySet(suite: cipherSuite, secret: secret, for: mode, ourPerspective: self.perspective)
            if self.canFlushHandshakeBuffer && mode != self.perspective {
                print("PacketProtectorHandler::InstallHandshakeKeys::Attempting to Read Buffered Handshake Packets...")
                self.decryptAndFlushHandshakeBuffer()
            }
        } catch {
            self.storedContext.fireErrorCaught(error)
        }
    }

    // This function should be called by our StateHandler
    public func installTrafficKeys(secret: [UInt8], for mode: EndpointRole, cipherSuite: CipherSuite = .ChaChaPoly_SHA256) {
        // Given the traffic secret generate the necessary keys for Traffic Packet Protection
        print("PacketProtectorHandler::InstallTrafficKeys:: 🔐 Generating and Installing \(mode) Key Set for Traffic Packet Protection 🔐")
        print("PacketProtectorHandler::InstallTrafficKeys::Using Secret: \(secret.hexString)")

        // Install the keys
        do {
            try self.trafficKeys.installKeySet(suite: cipherSuite, secret: secret, for: mode, ourPerspective: self.perspective)
            if self.canFlushTrafficBuffer && mode != self.perspective {
                print("PacketProtectorHandler::InstallTrafficKeys::Attempting to Read Buffered Traffic Packets...")
                self.decryptAndFlushTrafficBuffer()
            }
        } catch {
            self.storedContext.fireErrorCaught(error)
        }
    }

    public func allowHandshakeFlush() {
        guard self.canFlushHandshakeBuffer == false else { return }
        self.canFlushHandshakeBuffer = true
    }

    public func allowTrafficFlush() {
        guard self.canFlushTrafficBuffer == false else { return }
        self.canFlushTrafficBuffer = true
    }

    public func dropInitialKeys() {
        self.initialKeys.dropKeys()
    }

    public func dropHandshakeKeys() {
        self.handshakeKeys.dropKeys()
    }

    private func decryptAndFlushHandshakeBuffer() {
        print("PacketProtectorHandler::DecryptAndFlushHandshakeBuffer")
        while self.encryptedHandshakeBuffer.readableBytes > 0 {
            guard let packet = encryptedHandshakeBuffer.readEncryptedQuicHandshakePacket(using: self.handshakeKeys) else {
                print("PacketProtectorHandler::DecryptAndFlushHandshakeBuffer::Failed to Decrypt Buffered Handshake Packet")
                self.storedContext.fireErrorCaught(Errors.InvalidPacket)
                break
            }
            print("PacketProtectorHandler::DecryptAndFlushHandshakeBuffer::Flushing Buffer Handshake Packet")
            self.storedContext.fireChannelRead(self.wrapInboundOut(packet))
        }
    }

    private func decryptAndFlushTrafficBuffer() {
        print("PacketProtectorHandler::DecryptAndFlushTrafficBuffer")
        while self.encryptedTrafficBuffer.readableBytes > 0 {
            guard let packet = encryptedTrafficBuffer.readEncryptedQuicTrafficPacket(dcid: self.scid, using: self.trafficKeys) else {
                print("PacketProtectorHandler::DecryptAndFlushTrafficBuffer::Failed to Decrypt Buffered Traffic Packet")
                self.storedContext.fireErrorCaught(Errors.InvalidPacket)
                break
            }
            print("PacketProtectorHandler::DecryptAndFlushTrafficBuffer::Flushing Buffer Traffic Packet")
            self.storedContext.fireChannelRead(self.wrapInboundOut(packet))
        }
    }

    private func padDatagramIfNecessary(packets: inout [any Packet]) {
        // If the outbound datagram includes an InitialPacket, it needs to be padded to at least 1200 bytes
        if let initialPacketIndex = packets.firstIndex(where: { $0 as? InitialPacket != nil }) {
            guard var initialPacket = packets[initialPacketIndex] as? InitialPacket else { fatalError("PacketProtectorHandler::PadDatagramIfNecessary::InitialPacket turned out to not be an initial packet...") }
            // Get the total estimated bytes for all the packets
            var estimatedLength = 0
            for packet in packets {
                estimatedLength += packet.headerBytes.count + packet.serializedPayload.count + 16
            }

            guard estimatedLength < 1248 else { print("PacketProtectorHandler::PadDatagramIfNecessary::Warning::Packet payload exceeds 1248 bytes"); return }

            // Construct our Padding Frame of appropriate length
            let padding = Frames.Padding(length: 1248 - estimatedLength)

            // Inject the padding into our initial packet so it gets encrypted
            initialPacket.payload.insert(padding, at: 0)
            print("PacketProtectorHandler::PadDatagramIfNecessary::Adding \(1248 - estimatedLength) bytes of padding to our initial packet")

            // Update the packet in our packet array
            packets[initialPacketIndex] = initialPacket
        }

        // TODO: Check if short packet is long enough...
    }
}
