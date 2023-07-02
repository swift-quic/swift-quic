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

final class DatagramHandler: ChannelDuplexHandler {
    public typealias InboundIn = AddressedEnvelope<ByteBuffer>
    public typealias InboundOut = ByteBuffer
    public typealias OutboundIn = ByteBuffer
    public typealias OutboundOut = AddressedEnvelope<ByteBuffer>

    private let remoteAddress: SocketAddress

    init(remoteAddress: SocketAddress) {
        self.remoteAddress = remoteAddress
    }

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let datagram = self.unwrapInboundIn(data)
        context.fireChannelRead(self.wrapInboundOut(datagram.data))
    }

    public func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        let buffer = self.unwrapOutboundIn(data)
        context.write(self.wrapOutboundOut(AddressedEnvelope(remoteAddress: self.remoteAddress, data: buffer)), promise: promise)
    }
}

/// The only difference between this Handler and PacketProtectorHandler is that it opperates on ByteBuffers instead of AddressedEnvelopes
final class PacketProtectorHandler: ChannelDuplexHandler {
    public typealias InboundIn = ByteBuffer
    public typealias InboundOut = Packet
    public typealias OutboundIn = [any Packet] // This is an array, so we can explicitly coallese packets within a datagram
    public typealias OutboundOut = ByteBuffer

    private let perspective: EndpointRole
    private let originalDCID: ConnectionID
    private let scid: ConnectionID

    internal var initialKeys: PacketProtector
    internal var handshakeKeys: PacketProtector
    internal var trafficKeys: TrafficKeyRing
    private var storedContext: ChannelHandlerContext!
    private let remoteAddress: SocketAddress
    private var version: Version
    private var state: StateMachine

    private var canFlushHandshakeBuffer: Bool = false {
        didSet { if self.canFlushHandshakeBuffer && self.encryptedHandshakeBuffer.readableBytes > 0 && self.handshakeKeys.opener != nil { self.decryptAndFlushHandshakeBuffer() } }
    }

    internal var encryptedHandshakeBuffer: ByteBuffer = ByteBuffer()

    private var canFlushTrafficBuffer: Bool = false {
        didSet { if self.canFlushTrafficBuffer && self.encryptedTrafficBuffer.readableBytes > 0 && self.trafficKeys.currentKeys.opener != nil { self.decryptAndFlushTrafficBuffer() } }
    }

    internal var encryptedTrafficBuffer: ByteBuffer = ByteBuffer()

    init(initialDCID dcid: ConnectionID, scid: ConnectionID, versions: [Version], perspective: EndpointRole, remoteAddress: SocketAddress) {
        guard !versions.isEmpty else { fatalError("Supported Versions can't be empty") }
        self.perspective = perspective
        self.scid = scid
        self.originalDCID = dcid
        self.remoteAddress = remoteAddress
        self.state = StateMachine(supportedVersions: versions)
        self.version = versions.first!
        // Generate Initial Key Sets
        self.initialKeys = try! self.version.newInitialAEAD(connectionID: dcid, perspective: perspective)
        self.handshakeKeys = PacketProtector(epoch: .Handshake, version: self.version)
        self.trafficKeys = TrafficKeyRing(version: self.version)
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

        if self.state.isNegotiatingVersion {
            do {
                if let versionNegotiationPacket = buffer.readVersionNegotiationPacket() {
                    // We received a Version Negotiation Packet
                    try self.state.processVersionNegotiationPacket(versionNegotiationPacket)
                    // This updates our Keys
                    try self.updateVersion()
                    // Let our state handler know we've negotiated a different version
                    context.fireUserInboundEventTriggered(ConnectionChannelEvent.VersionNegotiated(version: self.version))
                    // The VersionNegotiationPacket should be this entire Datagram so we can return / stop processing here.
                    return
                } else {
                    // The server is okay with our proposed Version
                    try self.state.acceptedVersion()
                    // Go ahead and process inbound packets as usual...
                }
            } catch {
                context.fireUserInboundEventTriggered(ConnectionChannelEvent.FailedVersionNegotiation(error: "\(error)"))
            }
        }

        print("PacketProtectorHandler[\(self.perspective)]::ChannelRead::Envelope: \(buffer.readableBytes) bytes")

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
                        fatalError("PacketProtectorHandler[\(self.perspective)]::ChannelRead::Failed to decrypt initial packet")
                    }
                    packet = p
                case .Handshake:
                    guard self.handshakeKeys.opener != nil else {
                        print("PacketProtectorHandler[\(self.perspective)]::ChannelRead::Handshake Keys Not Available Yet! Buffering Handshake Packet")
                        guard let (_, totalPacketLength) = try? buffer.getLongHeaderPacketNumberOffsetAndTotalLength() else {
                            fatalError("PacketProtectorHandler[\(self.perspective)]::ChannelRead::Failed to fetch PNO and Length for Encrypted Handshake Packet")
                        }
                        guard var encryptedPacket = buffer.readSlice(length: totalPacketLength) else {
                            fatalError("PacketProtectorHandler[\(self.perspective)]::ChannelRead::Failed to fetch PNO and Length for Encrypted Handshake Packet")
                        }
                        self.encryptedHandshakeBuffer.writeBuffer(&encryptedPacket)
                        break
                    }
                    guard let p = buffer.readEncryptedQuicHandshakePacket(using: handshakeKeys) else {
                        fatalError("PacketProtectorHandler[\(self.perspective)]::ChannelRead::Failed to decrypt handshake packet")
                    }
                    packet = p
                case .Short:
                    guard self.trafficKeys.currentKeys.opener != nil else {
                        print("PacketProtectorHandler[\(self.perspective)]::ChannelRead::Traffic Keys Not Available Yet! Buffering Traffic Packet")
                        self.encryptedTrafficBuffer.writeBuffer(&buffer)
                        break
                    }
                    guard let header = buffer.readEncryptedQuicTrafficHeader(dcid: scid, using: trafficKeys.currentKeys) else {
                        fatalError("PacketProtectorHandler[\(self.perspective)]::ChannelRead::Failed to decrypt traffic packet")
                    }

                    guard let keyPhase = KeyPhase(rawValue: header.firstByte & KeyPhase.mask) else {
                        fatalError("PacketProtectorHandler[\(self.perspective)]::ChannelRead::Failed to determine traffic packet key phase")
                    }

                    if keyPhase != self.trafficKeys.currentKeyPhase {
                        // TODO: Keep track of Key Phase packet number and drop previous keys once all existing packets have been acknowledged
                        print("PacketProtectorHandler[\(self.perspective)]::Attempting to update Keys 🔐")
                        try! self.trafficKeys.updateKeys()
                        context.fireUserInboundEventTriggered(ConnectionChannelEvent.KeyUpdateInitiated(packetNumber: header.packetNumberAsUInt64(), initiator: self.perspective.opposite))
                    }

                    guard let p = buffer.readEncryptedQuicTrafficPayload(header: header, using: trafficKeys.keysFor(keyPhase)) else {
                        fatalError("PacketProtectorHandler[\(self.perspective)]::ChannelRead::Failed to decrypt traffic packet")
                    }
                    packet = p

                default:
                    fatalError("PacketProtectorHandler[\(self.perspective)]::ChannelRead::TODO:Handle Packet Type: \(PacketType(firstByte)!)")
            }
            if let packet {
                packetsToProcess.append(packet)
            }
        }

        // Send each packet along the pipeline
        print("PacketProtectorHandler[\(self.perspective)]::ChannelRead::We have \(packetsToProcess.count) Packets that need to be processed...")
        packetsToProcess.forEach { packet in
            print("PacketProtectorHandler[\(self.perspective)]::ChannelRead::Packet -> \(packet)")
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

            print("PacketProtectorHandler[\(self.perspective)]::Write::Encrypting Packet")
            print("PacketProtectorHandler[\(self.perspective)]::Write::\(packet)")
            guard !packet.payload.isEmpty else {
                print("PacketProtectionHandler[\(self.perspective)]::Write::Dropping Empty Packet")
                return
            }

            do {
                let enc: (protectedHeader: [UInt8], encryptedPayload: [UInt8])
                switch PacketType(packet.header.firstByte) {
                    case .Initial:
                        enc = try (packet as! InitialPacket).seal(using: self.initialKeys)
                    case .Handshake:
                        enc = try (packet as! HandshakePacket).seal(using: self.handshakeKeys)
                    case .Short:
                        var short = packet as! ShortPacket
                        short.header.setKeyPhaseBit(self.trafficKeys.currentKeyPhase)
                        enc = try (short).seal(using: self.trafficKeys.currentKeys)
                    default:
                        context.fireErrorCaught(Errors.InvalidPacket)
                        fatalError("PacketProtectorhandler[\(self.perspective)]::Write::Handle Packet Type \(PacketType(packet.header.firstByte)!)")
                }
                datagramPayload.writeBytes(enc.protectedHeader)
                datagramPayload.writeBytes(enc.encryptedPayload)
            } catch {
                fatalError("PacketProtectorhandler[\(self.perspective)]::Failed to encrypt packet `\(error)`")
            }
        }

        guard datagramPayload.readableBytes > 0 else {
            promise?.succeed()
            return
        }

        print("PacketProtectorHandler[\(self.perspective)]::Write::Sending Datagram")
        print("PacketProtectorHandler[\(self.perspective)]::Write::\(datagramPayload.readableBytes) bytes")
        context.writeAndFlush(self.wrapOutboundOut(datagramPayload), promise: promise)
    }

    // This function should be called by our StateHandler
    public func installHandshakeKeys(secret: [UInt8], for mode: EndpointRole, cipherSuite: CipherSuite = .AESGCM128_SHA256) {
        // Given the handshake secret generate the necessary keys for Handshake Packet Protection
        print("PacketProtectorHandler[\(self.perspective)]::InstallHandshakeKeys:: 🔐 Generating and Installing \(mode) Key Set for Handshake Packet Protection 🔐")
        print("PacketProtectorHandler[\(self.perspective)]::InstallHandshakeKeys::Using Secret: \(secret.hexString)")

        // Install the keys
        do {
            try self.handshakeKeys.installKeySet(suite: cipherSuite, secret: secret, for: mode, ourPerspective: self.perspective)
            if self.canFlushHandshakeBuffer && mode != self.perspective {
                print("PacketProtectorHandler[\(self.perspective)]::InstallHandshakeKeys::Attempting to Read Buffered Handshake Packets...")
                self.decryptAndFlushHandshakeBuffer()
            }
        } catch {
            print("PacketProtectorHandler[\(self.perspective)]::Error Caught::\(error)")
            self.storedContext.fireErrorCaught(error)
        }
    }

    // This function should be called by our StateHandler
    public func installTrafficKeys(secret: [UInt8], for mode: EndpointRole, cipherSuite: CipherSuite = .ChaChaPoly_SHA256) {
        // Given the traffic secret generate the necessary keys for Traffic Packet Protection
        print("PacketProtectorHandler[\(self.perspective)]::InstallTrafficKeys:: 🔐 Generating and Installing \(mode) Key Set for Traffic Packet Protection 🔐")
        print("PacketProtectorHandler[\(self.perspective)]::InstallTrafficKeys::Using Secret: \(secret.hexString)")

        // Install the keys
        do {
            try self.trafficKeys.installKeySet(suite: cipherSuite, secret: secret, for: mode, ourPerspective: self.perspective)
            print(self.trafficKeys)
            print(self.trafficKeys.currentKeys)
            if self.canFlushTrafficBuffer && mode != self.perspective {
                print("PacketProtectorHandler[\(self.perspective)]::InstallTrafficKeys::Attempting to Read Buffered Traffic Packets...")
                self.decryptAndFlushTrafficBuffer()
            }
        } catch {
            print("PacketProtectorHandler[\(self.perspective)]::Error Caught::\(error)")
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

    public func dropTrafficKeysForPreviousPhase() {
        self.trafficKeys.dropKeysForPreviousPhase()
    }

    public func initiateKeyUpdate(at pn: UInt64) {
        do {
            try self.trafficKeys.updateKeys()
            self.storedContext.fireUserInboundEventTriggered(ConnectionChannelEvent.KeyUpdateInitiated(packetNumber: pn, initiator: self.perspective))
        } catch {
            print("PacketProtectorHandler[\(self.perspective)]::Failed to Initiate Key Update -> \(error)")
        }
    }

    private func updateVersion() throws {
        guard case .versionNegotiation(let vnState) = self.state.state else { print("Can't update Version from state `\(self.state.state)`"); throw Errors.UnsupportedVersion }
        guard let negotiatedVersion = vnState.negotiatedVersion else { print("Failed to determine negotiated version"); throw Errors.UnsupportedVersion }
        print("PacketProtectorHandler[\(self.perspective)]::Attempting to update to Version: \(negotiatedVersion)")
        self.version = negotiatedVersion
        self.initialKeys = try negotiatedVersion.newInitialAEAD(connectionID: self.originalDCID, perspective: self.perspective)
        self.handshakeKeys = PacketProtector(epoch: .Handshake, version: negotiatedVersion)
        self.trafficKeys = TrafficKeyRing(version: negotiatedVersion)
        try self.state.doneUpdatingVersion()
    }

    private func decryptAndFlushHandshakeBuffer() {
        print("PacketProtectorHandler[\(self.perspective)]::DecryptAndFlushHandshakeBuffer")
        while self.encryptedHandshakeBuffer.readableBytes > 0 {
            guard let packet = encryptedHandshakeBuffer.readEncryptedQuicHandshakePacket(using: self.handshakeKeys) else {
                print("PacketProtectorHandler[\(self.perspective)]::DecryptAndFlushHandshakeBuffer::Failed to Decrypt Buffered Handshake Packet")
                self.storedContext.fireErrorCaught(Errors.InvalidPacket)
                break
            }
            print("PacketProtectorHandler[\(self.perspective)]::DecryptAndFlushHandshakeBuffer::Flushing Buffer Handshake Packet")
            self.storedContext.fireChannelRead(self.wrapInboundOut(packet))
        }
    }

    private func decryptAndFlushTrafficBuffer() {
        print("PacketProtectorHandler[\(self.perspective)]::DecryptAndFlushTrafficBuffer")
        while self.encryptedTrafficBuffer.readableBytes > 0 {
            guard let packet = encryptedTrafficBuffer.readEncryptedQuicTrafficPacket(dcid: self.scid, using: self.trafficKeys.currentKeys) else {
                print("PacketProtectorHandler[\(self.perspective)]::DecryptAndFlushTrafficBuffer::Failed to Decrypt Buffered Traffic Packet")
                self.storedContext.fireErrorCaught(Errors.InvalidPacket)
                break
            }
            print("PacketProtectorHandler[\(self.perspective)]::DecryptAndFlushTrafficBuffer::Flushing Buffer Traffic Packet")
            self.storedContext.fireChannelRead(self.wrapInboundOut(packet))
        }
    }

    private func padDatagramIfNecessary(packets: inout [any Packet]) {
        // If the outbound datagram includes an InitialPacket, it needs to be padded to at least 1200 bytes
        if let initialPacketIndex = packets.firstIndex(where: { $0 as? InitialPacket != nil }) {
            guard var initialPacket = packets[initialPacketIndex] as? InitialPacket else { fatalError("PacketProtectorHandler[\(self.perspective)]::PadDatagramIfNecessary::InitialPacket turned out to not be an initial packet...") }
            // Get the total estimated bytes for all the packets
            var estimatedLength = 0
            for packet in packets {
                estimatedLength += packet.headerBytes.count + packet.serializedPayload.count + 16
            }

            guard estimatedLength < 1248 else { print("PacketProtectorHandler[\(self.perspective)]::PadDatagramIfNecessary::Warning::Packet payload exceeds 1248 bytes"); return }

            // Construct our Padding Frame of appropriate length
            let padding = Frames.Padding(length: 1248 - estimatedLength)

            // Inject the padding into our initial packet so it gets encrypted
            initialPacket.payload.insert(padding, at: 0)
            print("PacketProtectorHandler[\(self.perspective)]::PadDatagramIfNecessary::Adding \(1248 - estimatedLength) bytes of padding to our initial packet")

            // Update the packet in our packet array
            packets[initialPacketIndex] = initialPacket
        }

        // TODO: Check if short packet is long enough...
    }
}

extension PacketProtectorHandler {
    /// Traffic Key Ring
    /// Attempts to handle
    /// https://datatracker.ietf.org/doc/html/rfc9001#section-6
    struct TrafficKeyRing {
        var currentKeyPhase: KeyPhase
        private(set) var cumulativePhase: UInt64 = 0
        private var trafficKeysPhase0: PacketProtector
        private var trafficKeysPhase1: PacketProtector

        init(version: Version) {
            self.currentKeyPhase = .not
            self.trafficKeysPhase0 = PacketProtector(epoch: .Application, version: version)
            self.trafficKeysPhase1 = PacketProtector(epoch: .Application, version: version)
        }

        var currentKeys: PacketProtector {
            self.keysFor(self.currentKeyPhase)
        }

        func keysFor(_ kp: KeyPhase) -> PacketProtector {
            switch kp {
                case .not:
                    return self.trafficKeysPhase0
                case .yes:
                    return self.trafficKeysPhase1
            }
        }

        mutating func installKeySet(suite: CipherSuite, secret: [UInt8], for mode: EndpointRole, ourPerspective: EndpointRole) throws {
            guard self.trafficKeysPhase1.opener == nil && self.trafficKeysPhase1.sealer == nil else { print("Can't install KeySets after Key Ring initialization. Use updateKeys() instead."); throw Errors.Crypto(0) }
            try self.trafficKeysPhase0.installKeySet(suite: suite, secret: secret, for: mode, ourPerspective: ourPerspective)
        }

        /// This method uses the existing keys to prepare a new set of traffic keys beloging to the new Key Phase.
        /// This method will throw if the keys from the previous phase haven't been dropped yet.
        /// Upon generating a new key set for the next key phase, this method will toggle our current traffic key phase and begin using the new keys.
        mutating func updateKeys() throws {
            switch self.currentKeyPhase {
                case .not:
                    guard self.trafficKeysPhase1.opener == nil && self.trafficKeysPhase1.sealer == nil else { throw Errors.Crypto(0) }
                    guard self.trafficKeysPhase0.opener != nil && self.trafficKeysPhase0.sealer != nil else { throw Errors.Crypto(0) }
                    try self.trafficKeysPhase1.updateKeys(using: self.trafficKeysPhase0)
                case .yes:
                    guard self.trafficKeysPhase0.opener == nil && self.trafficKeysPhase0.sealer == nil else { throw Errors.Crypto(0) }
                    guard self.trafficKeysPhase1.opener != nil && self.trafficKeysPhase1.sealer != nil else { throw Errors.Crypto(0) }
                    try self.trafficKeysPhase0.updateKeys(using: self.trafficKeysPhase1)
            }
            self.currentKeyPhase.toggle()
            self.cumulativePhase += 1
        }

        public mutating func dropKeysForPreviousPhase() {
            switch self.currentKeyPhase {
                case .not:
                    self.trafficKeysPhase1.dropKeys()
                case .yes:
                    self.trafficKeysPhase0.dropKeys()
            }
        }
    }
}

extension PacketProtectorHandler {
    /// A State Machine that the PacketProtectorHandler can use to handle Version Negotiation
    struct StateMachine {
        private(set) var state: State

        public var isNegotiatingVersion: Bool {
            switch self.state {
                case .versionNegotiation: return true
                default: return false
            }
        }

        enum State {
            case versionNegotiation(VersionNegotiationState)
            case active(ActiveState)
            case incompatible
        }

        struct VersionNegotiationState {
            let versions: [Version]
            var negotiatedVersion: Version? = nil

            mutating func negotiatedVersion(_ version: Version) throws {
                guard self.versions.contains(version) else { print("Chosen Version is not a supported Version"); throw Errors.UnsupportedVersion }
                guard self.negotiatedVersion == nil else { print("A version has already been negotiated"); throw Errors.UnsupportedVersion }
                self.negotiatedVersion = version
            }
        }

        struct ActiveState {
            let version: Version

            init(previous: VersionNegotiationState) {
                guard let negotiatedVersion = previous.negotiatedVersion else { fatalError("Can't enter Active State without a negotiated Version") }
                self.version = negotiatedVersion
            }
        }

        init(supportedVersions: [Version]) {
            self.state = .versionNegotiation(VersionNegotiationState(versions: supportedVersions))
        }

        init(negotiatiedVersion: Version) {
            self.state = .active(ActiveState(previous: VersionNegotiationState(versions: [], negotiatedVersion: negotiatiedVersion)))
        }

        public mutating func acceptedVersion() throws {
            switch self.state {
                case .versionNegotiation(var vnState):
                    guard let acceptedVersion = vnState.versions.first else { throw Errors.UnsupportedVersion }
                    try vnState.negotiatedVersion(acceptedVersion)
                    self.state = .active(ActiveState(previous: vnState))
                    print("Accepted Active Version: \(acceptedVersion)")
                case .active, .incompatible:
                    throw Errors.UnsupportedVersion
            }
        }

        public mutating func processVersionNegotiationPacket(_ vnPacket: VersionNegotiationPacket) throws {
            switch self.state {
                case .versionNegotiation(var vnState):
                    var match: Version?
                    for desiredVersion in vnState.versions {
                        if vnPacket.versions.contains(desiredVersion) {
                            // We've found a Version that we both agree with...
                            print("Selecting Version: \(desiredVersion)")
                            match = desiredVersion
                            break
                        }
                    }

                    if let match = match {
                        try vnState.negotiatedVersion(match)
                        self.state = .versionNegotiation(vnState)
                        print("Negotiated Version: \(match)")
                    } else {
                        print("No Supported Version Overlap with Server. Entering State -> Incompatible")
                        self.state = .incompatible
                    }

                case .active, .incompatible:
                    throw Errors.UnsupportedVersion
            }
        }

        public mutating func doneUpdatingVersion() throws {
            switch self.state {
                case .versionNegotiation(let vnState):
                    self.state = .active(ActiveState(previous: vnState))
                default:
                    throw Errors.UnsupportedVersion
            }
        }
    }
}
