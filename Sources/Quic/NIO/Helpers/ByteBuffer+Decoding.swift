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

/// Connection ID
extension ByteBuffer {
    /// This method attempts to get a VarInt Length Prefixed ConnectionID from the specified offset of this ByteBuffer.
    /// - Note: If either the VarInt reading or the ConnectionID read fails, the reader index is returned to it's original position...
    func getConnectionID(at offset: Int) -> ConnectionID? {
        if let bytes = self.getQuicVarIntLengthPrefixedBytes(at: offset) {
            return ConnectionID(with: bytes)
        } else {
            return nil
        }
    }

    /// This method attempts to read a VarInt Length Prefixed ConnectionID from the head of this ByteBuffer.
    /// - Note: If either the VarInt reading or the ConnectionID read fails, the reader index is returned to it's original position...
    mutating func readConnectionID() -> ConnectionID? {
        if let bytes = self.readQuicVarIntLengthPrefixedBytes() {
            return ConnectionID(with: bytes)
        } else {
            return nil
        }
    }

    mutating func writeConnectionID(_ cid: ConnectionID) {
        self.writeQuicVarIntLengthPrefixedBytes(cid.rawValue)
    }
}

/// Version
extension ByteBuffer {
    /// This method attempts to get a UInt32 at the specified offset and instantiate a Version from it (it doesn't guarantee a known / support Version).
    /// - Note: If either the VarInt reading or the ConnectionID read fails, the reader index is returned to it's original position...
    func getVersion(at offset: Int) -> Version? {
        guard let int = self.getInteger(at: offset, endianness: .big, as: UInt32.self) else { return nil }
        return Version(rawValue: int)
    }

    /// This method attempts to read a UInt32 and instantiate a Version from it (it doesn't guarantee a known / support Version).
    /// - Note: If the read fails then the readerIndex is rewound to it's original position.
    mutating func readVersion() -> Version? {
        guard self.readableBytes >= 4, let int = self.readInteger(endianness: .big, as: UInt32.self) else {
            return nil
        }
        return Version(rawValue: int)
    }

    mutating func writeVersion(_ version: Version) {
        self.writeQuicVarIntLengthPrefixedBytes(version.withUnsafeBytes { Array($0) })
    }
}

/// PacketNumberOffset
extension ByteBuffer {
    func getLongHeaderPacketNumberOffset(at initialOffset: Int, isInitial: Bool) throws -> (packetLength: UInt64, packetNumberOffset: Int) {
        // Header Byte and 4 Byte Version
        var offset = initialOffset + 5
        // Read DCID
        offset += try self.varIntLengthPrefixedByteCount(at: offset)
        // Read SCID
        offset += try self.varIntLengthPrefixedByteCount(at: offset)
        if isInitial {
            // Read the Token
            offset += try self.varIntLengthPrefixedByteCount(at: offset)
        }
        // Read the packet length VarInt
        guard let varInt = self.getQuicVarInt(at: offset) else { throw Errors.InvalidPacket }
        return (packetLength: varInt.value, packetNumberOffset: offset + varInt.length)
    }

    private func varIntLengthPrefixedByteCount(at offset: Int) throws -> Int {
        guard let varInt = self.getQuicVarInt(at: offset) else { throw Errors.InvalidPacket }
        return varInt.length + Int(varInt.value)
    }
}

extension ByteBuffer {
    // We should be directly mutating the buffer
    mutating func removeLongHeaderProtection(at headerOffset: Int, packetNumberOffset: Int, sampleSize: Int, using opener: Opener) throws -> Int {
        guard let sample = self.getBytes(at: packetNumberOffset + 4, length: sampleSize) else { throw Errors.InvalidPacket }
        guard var header = self.getBytes(at: headerOffset, length: packetNumberOffset + 4 - headerOffset) else { throw Errors.InvalidPacket }
        try opener.removeHeaderProtection(sample: sample, hdrBytes: &header, packetNumberOffset: packetNumberOffset)
        self.setBytes(header, at: 0)
        return header.count
    }

    // We should be directly mutating the buffer
    mutating func removeShortHeaderProtection(at headerOffset: Int, packetNumberOffset: Int, sampleSize: Int, using opener: Opener) throws -> Int {
        guard let sample = self.getBytes(at: packetNumberOffset + 4, length: sampleSize) else { throw Errors.InvalidPacket }
        guard var header = self.getBytes(at: headerOffset, length: packetNumberOffset + 4 - headerOffset) else { throw Errors.InvalidPacket }
        try opener.removeHeaderProtection(sample: sample, hdrBytes: &header, packetNumberOffset: packetNumberOffset)
        self.setBytes(header, at: 0)
        return header.count
    }

    internal enum PaddingRemoval {
        case dropTrailingZeros
        case dropLeadingZeros
        case doNothing
    }

    mutating func decryptBytes(at offset: Int, packetLength: Int, headerOffset: Int, packetNumber: [UInt8], using opener: Opener, paddingRemovalStrategy: PaddingRemoval = .doNothing) throws {
        guard let header = self.getBytes(at: headerOffset, length: offset - headerOffset) else { throw Errors.InvalidPacket }
        guard let ciphertext = self.getBytes(at: offset, length: packetLength - packetNumber.count) else { print("Not enough ciphertext bytes: Offset: \(offset), Length: \(packetLength), Bytes Available: \(self.readableBytes)"); throw Errors.InvalidPacket }

        let plaintext = try opener.decryptPayload(cipherText: ciphertext, packetNumber: packetNumber, unprotectedHeaderBytes: header)

        let endIndex = offset + (packetLength - packetNumber.count)

        var paddingCount = 0
        switch paddingRemovalStrategy {
            case .dropTrailingZeros:
                // To remove trailing padding...
                while plaintext[plaintext.count - paddingCount - 1] == 0 { paddingCount += 1 }
                // Set the header and unpadded plaintext to the end of the ByteBuffer segment
                self.setBytes(header + plaintext.dropLast(paddingCount), at: endIndex - header.count - (plaintext.count - paddingCount))
            case .dropLeadingZeros:
                // To remove leading padding...
                while plaintext[paddingCount] == 0 { paddingCount += 1 }
                // Set the header and unpadded plaintext to the end of the ByteBuffer segment
                self.setBytes(header + plaintext.dropFirst(paddingCount), at: endIndex - header.count - (plaintext.count - paddingCount))
            case .doNothing:
                self.setBytes(header + plaintext, at: endIndex - header.count - (plaintext.count - paddingCount))
        }

        // Move the reader to the start of the unprotected header
        self.moveReaderIndex(to: headerOffset + paddingCount + 16)
    }
}

extension ByteBuffer {
    @usableFromInline
    enum ReadResult<T> {
        case invalidFrame
        case needMoreData
        case success(T)
    }
    
    @inlinable
    func optionallyUnwraped<T>(_ result: ReadResult<T>) -> T? {
        switch result {
            case .invalidFrame, .needMoreData: return nil
            case .success(let t):
                return t
        }
    }
    
    /// Attempts to consume a Quic Crypto Frame and returns the bytes upon success
    ///
    /// - returns: A `[UInt8]` value containing the `CryptoFrame`s bytes or `nil` if there wasn't a valid frame available.
    @inlinable
    mutating func readQuicCryptoFrame() -> [UInt8]? {
        guard self.getBytes(at: self.readerIndex, length: 1) == [0x06] else { print("ReadQuicCryptoFrame::Invalid Frame Type"); return nil }
        guard let offset = self.getQuicVarInt(at: self.readerIndex + 1) else { print("ReadQuicCryptoFrame::Failed to get Offset"); return nil }
        //print("QuicCryptoFrame::Offset Bytes \(offset.length)")
        guard let length = self.getQuicVarInt(at: self.readerIndex + offset.length + 1) else { print("ReadQuicCryptoFrame::Failed to get Length"); return nil }
        //print("QuicCryptoFrame::Length Bytes \(length.length)")
        let bytesToConsume = 1 + offset.length + length.length + Int(length.value)
        guard let result = self.getBytes(at: self.readerIndex, length: bytesToConsume) else {
            print("QuicCryptoFrame::Not enough bytes available")
            return nil
        }
        self.moveReaderIndex(forwardBy: bytesToConsume)
        return result
    }
    
    @inlinable
    mutating func readQuicCryptoFrameContents() -> [UInt8]? {
        guard self.getBytes(at: self.readerIndex, length: 1) == [0x06] else { return nil }
        guard let offset = self.getQuicVarInt(at: self.readerIndex + 1) else { return nil }
        //print("QuicCryptoFrame::Offset Bytes \(offset.length)")
        guard let length = self.getQuicVarInt(at: self.readerIndex + offset.length + 1) else { return nil }
        //print("QuicCryptoFrame::Length Bytes \(length.length)")
        let frameHeaderLength = 1 + offset.length + length.length
        let framePayloadLength = Int(length.value)
        guard let result = self.getBytes(at: self.readerIndex + frameHeaderLength, length: framePayloadLength) else {
            return nil
        }
        self.moveReaderIndex(forwardBy: frameHeaderLength + framePayloadLength)
        return result
    }
}




extension ByteBuffer {

    /// Attempts to consume and Decrypt a QUIC InitialPacket and returns the packet upon success
    ///
    /// - returns: An `InitialPacket` or `nil` if there wasn't a valid packet available or if an error was encountered...
    //@inlinable
    mutating func readEncryptedQuicInitialPacket(using keys: PacketProtector) -> InitialPacket? {
        // Grab the first byte
        guard let protectedFirstByte = self.getBytes(at: self.readerIndex, length: 1)?.first else { return nil }
        // Ensure the first byte indicates that this is an Initial Packet Type
        guard LongPacketType(rawValue: protectedFirstByte & LongPacketType.mask) == .initial else { return nil }
        // Get the Packet Length
        guard let (pno, totalPacketLength) = try? self.getLongHeaderPacketNumberOffsetAndTotalLength() else { return nil }
        guard let bytes = self.getBytes(at: self.readerIndex, length: totalPacketLength) else { return nil }
        guard let opened = try? keys.open(bytes: bytes, packetNumberOffset: pno) else { return nil }
        //print("Decrypted InitialPacket")
        //print("Header: \(opened.header.hexString)")
        //print("Payload: \(opened.payload.hexString)")
        var headerBuf = ByteBuffer(bytes: opened.header)
        guard let firstByte = headerBuf.readBytes(length: 1)?.first, LongPacketType(rawValue: firstByte & LongPacketType.mask) == .initial else { return nil }
        guard let version = headerBuf.readVersion() else { print("Failed to consume Version from Header"); return nil }
        guard let dcid = headerBuf.readConnectionID() else { print("Failed to consume DCID from Header"); return nil }
        guard let scid = headerBuf.readConnectionID() else { print("Failed to consume SCID from Header"); return nil }
        guard let token = headerBuf.readQuicVarIntLengthPrefixedBytes() else { print("Failed to consume Token from Header"); return nil }
        guard headerBuf.readQuicVarInt() != nil else { print("Failed to consume PacketLength from Header"); return nil }
        guard let packetNumber = headerBuf.readBytes(length: headerBuf.readableBytes) else { print("Failed to consume PacketNumber from Header"); return nil }

        let initialHeader = InitialHeader(version: version, destinationID: dcid, sourceID: scid, token: token, packetNumber: packetNumber)
        guard let frames = try? opened.payload.parsePayloadIntoFrames() else { print("Failed to parse payload into Frames"); return nil }
        let initialPacket = InitialPacket(header: initialHeader, payload: frames.frames)

        self.moveReaderIndex(forwardBy: totalPacketLength)
        return initialPacket
    }

    /// Attempts to consume and Decrypt a QUIC HandshakePacket and returns the packet upon success
    ///
    /// - returns: A `HandshakePacket` or `nil` if there wasn't a valid packet available or if an error was encountered...
    //@inlinable
    mutating func readEncryptedQuicHandshakePacket(using keys: PacketProtector) -> HandshakePacket? {
        // Grab the first byte
        guard let protectedFirstByte = self.getBytes(at: self.readerIndex, length: 1)?.first else { print("No bytes available to Read"); return nil }
        // Ensure the first byte indicates that this is an Initial Packet Type
        guard LongPacketType(rawValue: protectedFirstByte & LongPacketType.mask) == .handshake else { print("Not a HandshakePacket"); return nil }
        do {
            // Get the Packet Length
            let (pno, totalPacketLength) = try self.getLongHeaderPacketNumberOffsetAndTotalLength()
            //print("Packet Number Offset: \(pno)")
            //print("Total Packet Length: \(totalPacketLength)")
            guard let bytes = self.getBytes(at: self.readerIndex, length: totalPacketLength) else { print("Not Enough Bytes Available"); return nil }

            let opened = try keys.open(bytes: bytes, packetNumberOffset: pno)
            //print("Decrypted HandshakePacket")
            //print("Header: \(opened.header.hexString)")
            //print("Payload: \(opened.payload.hexString)")
            var headerBuf = ByteBuffer(bytes: opened.header)
            guard let firstByte = headerBuf.readBytes(length: 1)?.first, LongPacketType(rawValue: firstByte & LongPacketType.mask) == .handshake else { print("Not a HandshakePacket"); return nil }
            guard let version = headerBuf.readVersion() else { print("Failed to consume Version from Header"); return nil }
            guard let dcid = headerBuf.readConnectionID() else { print("Failed to consume DCID from Header"); return nil }
            guard let scid = headerBuf.readConnectionID() else { print("Failed to consume SCID from Header"); return nil }
            guard headerBuf.readQuicVarInt() != nil else { print("Failed to consume PacketLength from Header"); return nil }
            guard let packetNumber = headerBuf.readBytes(length: headerBuf.readableBytes) else { print("Failed to consume PacketNumber from Header"); return nil }

            let handshakeHeader = HandshakeHeader(version: version, destinationID: dcid, sourceID: scid, packetNumber: packetNumber)
            guard let frames = try? opened.payload.parsePayloadIntoFrames() else { print("Failed to parse payload into Frames"); return nil }
            let handshakePacket = HandshakePacket(header: handshakeHeader, payload: frames.frames)

            self.moveReaderIndex(forwardBy: totalPacketLength)
            return handshakePacket
        } catch {
            print("Failed to read and decrypt handshake packet: \(error)")
            return nil
        }
    }

    /// Attempts to consume and Decrypt a QUIC Application / Traffic / Short Packet and returns the packet upon success
    /// - Parameters:
    ///   - dcid: The current Destination Connection ID associated with this Connection.
    ///   - keys: The `PacketProtector` containing the `Opener` used to remove this packets header protection and decrypt the payload.
    /// - returns: A `ShortPacket` or `nil` if there wasn't a valid packet available or if an error was encountered...
    mutating func readEncryptedQuicTrafficPacket(dcid: ConnectionID, using keys: PacketProtector) -> ShortPacket? {
        // Grab the first byte
        guard let protectedFirstByte = self.getBytes(at: self.readerIndex, length: 1)?.first else { print("No bytes available to Read"); return nil }
        // Ensure the first byte indicates that this is an Initial Packet Type
        guard HeaderForm(rawValue: protectedFirstByte & HeaderForm.mask) == .short else { print("Not a Traffic Packet"); return nil }
        do {
            // Get the Packet Length
            let pno = 1 + dcid.length
            //print("Packet Number Offset: \(pno)")
            guard let bytes = self.getBytes(at: self.readerIndex, length: self.readableBytes) else { print("Not Enough Bytes Available"); return nil }

            let opened = try keys.open(bytes: bytes, packetNumberOffset: pno)
            //print("Decrypted TrafficPacket")
            //print("Header: \(opened.header.hexString)")
            //print("Payload: \(opened.payload.hexString)")
            var headerBuf = ByteBuffer(bytes: opened.header)
            guard let firstByte = headerBuf.readBytes(length: 1)?.first, HeaderForm(rawValue: firstByte & HeaderForm.mask) == .short else { print("Not a TrafficPacket"); return nil }
            guard dcid.rawValue == headerBuf.readBytes(length: dcid.length) else { print("Failed to consume DCID from Header"); return nil }
            guard let packetNumber = headerBuf.readBytes(length: headerBuf.readableBytes) else { print("Failed to consume PacketNumber from Header"); return nil }

            let shortHeader = GenericShortHeader(firstByte: firstByte, id: dcid, packetNumber: packetNumber)
            guard let frames = try? opened.payload.parsePayloadIntoFrames() else { print("Failed to parse payload into Frames"); return nil }
            let shortPacket = ShortPacket(header: shortHeader, payload: frames.frames)

            self.moveReaderIndex(forwardBy: self.readableBytes)
            return shortPacket
        } catch {
            print("Failed to read and decrypt traffic packet: \(error)")
            return nil
        }
    }

    /// Attempts to consume and Decrypt a QUIC Application / Traffic / Short Packet Header and returns the Header upon success
    /// - Parameters:
    ///   - dcid: The current Destination Connection ID associated with this Connection.
    ///   - keys: The `PacketProtector` containing the `Opener` used to remove this packets header protection.
    /// - returns: A `GenericShortHeader` or `nil` if there wasn't a valid header available or if an error was encountered...
    mutating func readEncryptedQuicTrafficHeader(dcid: ConnectionID, using keys: PacketProtector) -> GenericShortHeader? {
        // Grab the first byte
        guard let protectedFirstByte = self.getBytes(at: self.readerIndex, length: 1)?.first else { print("No bytes available to Read"); return nil }
        // Ensure the first byte indicates that this is an Initial Packet Type
        guard HeaderForm(rawValue: protectedFirstByte & HeaderForm.mask) == .short else { print("Not a Traffic Packet"); return nil }
        do {
            // Get the Packet Length
            let pno = 1 + dcid.length
            guard let bytes = self.getBytes(at: self.readerIndex, length: self.readableBytes) else { print("Not Enough Bytes Available"); return nil }

            let sampleOffset = pno + 4
            guard let sample = self.getBytes(at: self.readerIndex + sampleOffset, length: 16) else { print("Not Enough Bytes Available For Sample"); return nil }
            var hb = Array(bytes[..<(pno + 4)])
            try keys.removeHeaderProtection(sample: sample, headerBytes: &hb, packetNumberOffset: pno)

            var headerBuf = ByteBuffer(bytes: hb)
            guard let firstByte = headerBuf.readBytes(length: 1)?.first, HeaderForm(rawValue: firstByte & HeaderForm.mask) == .short else { print("Not a TrafficPacket"); return nil }
            guard dcid.rawValue == headerBuf.readBytes(length: dcid.length) else { print("Failed to consume DCID from Header"); return nil }
            guard let packetNumber = headerBuf.readBytes(length: headerBuf.readableBytes) else { print("Failed to consume PacketNumber from Header"); return nil }

            let header = GenericShortHeader(firstByte: firstByte, id: dcid, packetNumber: packetNumber)
            self.moveReaderIndex(forwardBy: hb.count)

            return header
        } catch {
            print("Failed to read header for Short Packet: \(error)")
            return nil
        }
    }

    /// Attempts to consume and Decrypt a QUIC Application / Traffic / Short Packet Payload and returns the payload upon success
    /// - Parameters:
    ///   - header: The unprotected header associated with this packet
    ///   - keys: The `PacketProtector` containing the `Opener` used to decrypt this packets payload
    /// - returns: A `ShortPacket` or `nil` if there wasn't a valid header available or if an error was encountered...
    mutating func readEncryptedQuicTrafficPayload(header: GenericShortHeader, using keys: PacketProtector) -> ShortPacket? {
        do {
            let decryptedPayload = try keys.decryptPayload(Array(self.readableBytesView), packetNumber: header.packetNumber, authenticatingData: header.bytes)
            let packet = try ShortPacket(header: header, payload: decryptedPayload.parsePayloadIntoFrames().frames)
            self.moveReaderIndex(forwardBy: decryptedPayload.count + keys.suite!.tagLength)
            return packet
        } catch {
            print("Failed to decrypt payload for Short Packet: \(error)")
            return nil
        }
    }
}

extension ByteBuffer {
    // Returns the entire packet's length including the header
    func getQuicPacketLength() throws -> Int {
        guard let firstByte = self.getBytes(at: self.readerIndex, length: 1)?.first else { throw Errors.InvalidPacket }
        guard let type = LongPacketType(rawValue: firstByte & LongPacketType.mask) else { throw Errors.InvalidPacket }
        var tempReaderIndex: Int = self.readerIndex + 5 // First Byte and 4 Byte Version
        guard let dcidLength = self.getVarIntPrefixedBytesCount(at: tempReaderIndex) else { throw Errors.InvalidPacket }
        tempReaderIndex += dcidLength
        guard let scidLength = self.getVarIntPrefixedBytesCount(at: tempReaderIndex) else { throw Errors.InvalidPacket }
        tempReaderIndex += scidLength
        // If Initial, then read the token
        if type == .initial {
            guard let tokenLength = self.getVarIntPrefixedBytesCount(at: tempReaderIndex) else { throw Errors.InvalidPacket }
            tempReaderIndex += tokenLength
        }
        // Read Packet Length
        guard let packetLength = self.getQuicVarInt(at: tempReaderIndex) else { throw Errors.InvalidPacket }
        return (tempReaderIndex - self.readerIndex) + packetLength.length + Int(packetLength.value)
    }

    func getLongHeaderPacketNumberOffset() throws -> Int {
        guard let firstByte = self.getBytes(at: self.readerIndex, length: 1)?.first else { throw Errors.InvalidPacket }
        guard let type = LongPacketType(rawValue: firstByte & LongPacketType.mask) else { throw Errors.InvalidPacket }
        var tempReaderIndex: Int = self.readerIndex + 5 // First Byte and 4 Byte Version
        guard let dcidLength = self.getVarIntPrefixedBytesCount(at: tempReaderIndex) else { throw Errors.InvalidPacket }
        tempReaderIndex += dcidLength
        guard let scidLength = self.getVarIntPrefixedBytesCount(at: tempReaderIndex) else { throw Errors.InvalidPacket }
        tempReaderIndex += scidLength
        // If Initial, then read the token
        if type == .initial {
            guard let tokenLength = self.getVarIntPrefixedBytesCount(at: tempReaderIndex) else { throw Errors.InvalidPacket }
            tempReaderIndex += tokenLength
        }
        // Read Packet Length
        guard let packetLength = self.getQuicVarInt(at: tempReaderIndex) else { throw Errors.InvalidPacket }
        tempReaderIndex += packetLength.length

        return tempReaderIndex - self.readerIndex
    }

    func getLongHeaderPacketNumberOffsetAndTotalLength() throws -> (pno: Int, totalPacketLength: Int) {
        guard let firstByte = self.getBytes(at: self.readerIndex, length: 1)?.first else { print("PNO+TotalLength::Failed to read first byte"); throw Errors.InvalidPacket }
        guard let type = LongPacketType(rawValue: firstByte & LongPacketType.mask) else { print("PNO+TotalLength::Failed to determine packet type"); throw Errors.InvalidPacket }
        var tempReaderIndex: Int = self.readerIndex + 5 // First Byte and 4 Byte Version
        guard let dcidLength = self.getVarIntPrefixedBytesCount(at: tempReaderIndex) else { print("PNO+TotalLength::Failed to read dcid"); throw Errors.InvalidPacket }
        tempReaderIndex += dcidLength
        guard let scidLength = self.getVarIntPrefixedBytesCount(at: tempReaderIndex) else { print("PNO+TotalLength::Failed to read scid"); throw Errors.InvalidPacket }
        tempReaderIndex += scidLength
        // If Initial, then read the token
        if type == .initial {
            guard let tokenLength = self.getVarIntPrefixedBytesCount(at: tempReaderIndex) else { print("PNO+TotalLength::Failed to read token length"); throw Errors.InvalidPacket }
            tempReaderIndex += tokenLength
        }
        // Read Packet Length
        guard let packetLength = self.getQuicVarInt(at: tempReaderIndex) else { print("PNO+TotalLength::Failed to read packetLength"); throw Errors.InvalidPacket }
        tempReaderIndex += packetLength.length

        // Now remove the original offset...
        tempReaderIndex -= self.readerIndex

        return (pno: tempReaderIndex, totalPacketLength: tempReaderIndex + Int(packetLength.value))
    }

    func getShortHeaderPacketNumberOffset(dcid: ConnectionID) -> Int {
        1 + dcid.length
    }

    func getVarIntPrefixedBytesCount(at offset: Int) -> Int? {
        guard let varInt = self.getQuicVarInt(at: offset) else { return nil }
        return varInt.length + Int(varInt.value)
    }

    func getQuicCryptoFrameContents() -> [UInt8]? {
        guard self.getBytes(at: self.readerIndex, length: 1) == [0x06] else { return nil }
        guard let offset = self.getQuicVarInt(at: self.readerIndex + 1) else { return nil }
        //print("QuicCryptoFrame::Offset Bytes \(offset.length)")
        guard let length = self.getQuicVarInt(at: self.readerIndex + offset.length + 1) else { return nil }
        //print("QuicCryptoFrame::Length Bytes \(length.length)")
        let frameHeaderLength = 1 + offset.length + length.length
        let framePayloadLength = Int(length.value)
        guard let result = self.getBytes(at: self.readerIndex + frameHeaderLength, length: framePayloadLength) else {
            return nil
        }
        return result
    }

    mutating func readVersionNegotiationPacket() -> VersionNegotiationPacket? {
        self.rewindReaderOnNil { `self` -> VersionNegotiationPacket? in
            // The first byte only tells us that it's a Long Form Header (1st bit, the last 7 bits are unused / artbitrary)
            guard let firstByte = self.readBytes(length: 1)?.first else { return nil }
            let form = HeaderForm(rawValue: firstByte & HeaderForm.mask)
            guard case .long = form else { return nil }

            // The fact that the Version is set to 0 is the indicating factor that this is a Version negotiation packet
            guard let version = self.readVersion() else { return nil }
            guard version.rawValue == 0 else { return nil }

            guard let dcid = self.readConnectionID() else { return nil }
            guard let scid = self.readConnectionID() else { return nil }

            var supportedVersions: [Version] = []
            while self.readableBytes > 0, let v = self.readVersion() {
                supportedVersions.append(v)
            }

            guard self.readableBytes == 0 else { return nil }

            return VersionNegotiationPacket(destinationID: dcid, sourceID: scid, supportedVersions: supportedVersions)
        }
    }
}

extension ByteBuffer {
    @inlinable
    func _getSpaceTerminatedStringLength(at index: Int) -> Int? {
        guard self.readerIndex <= index && index < self.writerIndex else {
            return nil
        }
        guard let endIndex = self.readableBytesView[index...].firstIndex(of: 0x20) else {
            return nil
        }
        return endIndex &- index
    }

    @inlinable
    public func getBytesUpToNextSpace(at startIndex: Int) -> [UInt8]? {
        guard let length = self._getSpaceTerminatedStringLength(at: startIndex) else {
            return nil
        }
        return self.getBytes(at: startIndex, length: length)
    }

    /// Read a space terminated string off this `ByteBuffer`, decoding it as `String` using the UTF-8 encoding. Move the reader index
    /// forward by the string's length and its null terminator.
    ///
    /// - returns: A `String` value deserialized from this `ByteBuffer` or `nil` if there isn't a complete null-terminated string,
    ///            including null-terminator, in the readable bytes of the buffer
    @inlinable
    public func getSpaceTerminatedString(at startIndex: Int) -> String? {
        guard let stringLength = self._getSpaceTerminatedStringLength(at: startIndex) else {
            return nil
        }
        return self.getString(at: startIndex, length: stringLength)
    }

    /// Read a space terminated string off this `ByteBuffer`, decoding it as `String` using the UTF-8 encoding. Move the reader index
    /// forward by the string's length and its null terminator.
    ///
    /// - returns: A `String` value deserialized from this `ByteBuffer` or `nil` if there isn't a complete null-terminated string,
    ///            including null-terminator, in the readable bytes of the buffer
    @inlinable
    public mutating func readSpaceTerminatedString() -> String? {
        guard let stringLength = self._getSpaceTerminatedStringLength(at: self.readerIndex) else {
            return nil
        }
        let result = self.readString(length: stringLength)
        self.moveReaderIndex(forwardBy: 1) // move forward by space terminator
        return result
    }

    /// Read a space terminated string off this `ByteBuffer`, decoding it as `String` using the UTF-8 encoding. Move the reader index
    /// forward by the string's length and its null terminator.
    ///
    /// - returns: A `String` value deserialized from this `ByteBuffer` or `nil` if there isn't a complete null-terminated string,
    ///            including null-terminator, in the readable bytes of the buffer
    @inlinable
    public mutating func readSpaceTerminatedBytes() -> [UInt8]? {
        guard let stringLength = self._getSpaceTerminatedStringLength(at: self.readerIndex) else {
            return nil
        }
        let result = self.readBytes(length: stringLength)
        self.moveReaderIndex(forwardBy: 1) // move forward by space terminator
        return result
    }
}
