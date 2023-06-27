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
    public enum ReadResult {
        case invalidFrame
        case needMoreData
        case success([UInt8])
    }
    
    /// Attempts to consume a Quic Crypto Frame and returns the bytes upon success
    ///
    /// - returns: A `[UInt8]` value containing the `CryptoFrame`s bytes or `nil` if there wasn't a valid frame available.
    //@inlinable
    public mutating func readQuicCryptoFrame() -> [UInt8]? {
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

    public mutating func readQuicCryptoFrameContents() -> [UInt8]? {
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

    /// Attempts to consume a TLS ServerHello Frame and returns the bytes upon success
    ///
    /// - returns: A `[UInt8]` value containing the `TLS ServerHello`s bytes or `nil` if there wasn't a valid frame available.
    //@inlinable
    public mutating func readTLSClientHello() -> ReadResult {
        let result = self.getTLSClientHello()
        if case .success(let clientHello) = result {
            self.moveReaderIndex(forwardBy: clientHello.count)
        }
        return result
    }
    
    /// Attempts to consume a TLS ServerHello Frame and returns the bytes upon success
    ///
    /// - returns: A `[UInt8]` value containing the `TLS ServerHello`s bytes or `nil` if there wasn't a valid frame available.
    //@inlinable
    public mutating func readTLSServerHello() -> ReadResult {
        let result = self.getTLSServerHello()
        if case .success(let serverHello) = result {
            self.moveReaderIndex(forwardBy: serverHello.count)
        }
        return result
    }

    /// Attempts to consume a TLS Encrypted Extensions Frame and returns the bytes upon success
    ///
    /// - returns: A `[UInt8]` value containing the `TLS Encrypted Extension`s bytes or `nil` if there wasn't a valid frame available.
    //@inlinable
    public mutating func readTLSEncryptedExtensions() -> ReadResult {
        let result = self.getTLSEncryptedExtensions()
        if case .success(let encryptedExtensions) = result {
            self.moveReaderIndex(forwardBy: encryptedExtensions.count)
        }
        return result
    }

    /// Attempts to consume a TLS Certificate Frame and returns the bytes upon success
    ///
    /// - returns: A `[UInt8]` value containing the `TLS Certificate`s bytes or `nil` if there wasn't a valid frame available.
    //@inlinable
    public mutating func readTLSCertificate() -> ReadResult {
        let result = self.getTLSCertificate()
        if case .success(let certificate) = result {
            self.moveReaderIndex(forwardBy: certificate.count)
        }
        return result
    }

    /// Attempts to consume a TLS Certificate Verify Frame and returns the bytes upon success
    ///
    /// - returns: A `[UInt8]` value containing the `TLS Certificate Verify`s bytes or `nil` if there wasn't a valid frame available.
    //@inlinable
    public mutating func readTLSCertificateVerify() -> ReadResult {
        let result = self.getTLSCertificateVerify()
        if case .success(let certVerify) = result {
            self.moveReaderIndex(forwardBy: certVerify.count)
        }
        return result
    }

    /// Attempts to consume a TLS Certificate Verify Frame and returns the bytes upon success
    ///
    /// - returns: A `[UInt8]` value containing the `TLS Certificate Verify`s bytes or `nil` if there wasn't a valid frame available.
    //@inlinable
    public mutating func readTLSHandshakeFinished() -> ReadResult {
        let result = self.getTLSHandshakeFinished()
        if case .success(let finished) = result {
            self.moveReaderIndex(forwardBy: finished.count)
        }
        return result
    }

    // TODO: Doesn't handle Additional ACK Ranges or ECN Counts
    public mutating func readQuicACKFrame() -> [UInt8]? {
        guard let firstByte = self.getBytes(at: self.readerIndex, length: 1)?.first else { return nil }
        guard firstByte == 0x02 || firstByte == 0x03 else { return nil }
        guard let largestAcked = self.getQuicVarInt(at: self.readerIndex + 2) else { return nil }
        guard let ackDelay = self.getQuicVarInt(at: self.readerIndex + 2) else { return nil }
        guard let ackRangeCount = self.getQuicVarInt(at: self.readerIndex + 2) else { return nil }
        guard let firstAckRange = self.getQuicVarInt(at: self.readerIndex + 2) else { return nil }
        let bytesToConsume = 1 + Int(largestAcked.length + ackDelay.length + ackRangeCount.length + firstAckRange.length)
        guard let result = self.getBytes(at: self.readerIndex, length: bytesToConsume) else {
            return nil
        }
        self.moveReaderIndex(forwardBy: bytesToConsume)
        return result
    }

    /// Attempts to consume and Decrypt a QUIC InitialPacket and returns the packet upon success
    ///
    /// - returns: A n`InitialPacket` or `nil` if there wasn't a valid packet available or if an error was encountered...
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
        guard let packetLength = headerBuf.readQuicVarInt() else { print("Failed to consume PacketLength from Header"); return nil }
        guard let packetNumber = headerBuf.readBytes(length: headerBuf.readableBytes) else { print("Failed to consume PacketNumber from Header"); return nil }

        let initialHeader = InitialHeader(version: version, destinationID: dcid, sourceID: scid, token: token, packetNumber: packetNumber)
        guard let frames = try? opened.payload.parsePayloadIntoFrames() else { print("Failed to parse payload into Frames"); return nil }
        let initialPacket = InitialPacket(header: initialHeader, payload: frames.frames)

        self.moveReaderIndex(forwardBy: totalPacketLength)
        return initialPacket
    }

    /// Attempts to consume and Decrypt a QUIC InitialPacket and returns the packet upon success
    ///
    /// - returns: A n`InitialPacket` or `nil` if there wasn't a valid packet available or if an error was encountered...
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
            guard let packetLength = headerBuf.readQuicVarInt() else { print("Failed to consume PacketLength from Header"); return nil }
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

    /// Attempts to consume a TLS ClientHello Frame and returns the bytes upon success
    ///
    /// - returns: A `[UInt8]` value containing the `TLS ClientHello`s bytes or `nil` if there wasn't a valid frame available.
    //@inlinable
    public func getTLSClientHello() -> ReadResult {
        guard self.getBytes(at: self.readerIndex, length: 2) == [0x01, 0x00] else { return .invalidFrame }
        guard let length = self.getInteger(at: self.readerIndex + 2, as: UInt16.self) else { return .invalidFrame }
        let bytesToConsume = 4 + Int(length)
        guard let result = self.getBytes(at: self.readerIndex, length: bytesToConsume) else {
            return .needMoreData
        }
        return .success(result)
    }

    public func getTLSClientHelloSlice() -> ByteBuffer? {
        guard self.getBytes(at: self.readerIndex, length: 2) == [0x01, 0x00] else { return nil }
        guard let length = self.getInteger(at: self.readerIndex + 2, as: UInt16.self) else { return nil }
        let bytesToConsume = 4 + Int(length)
        guard let result = self.getSlice(at: self.readerIndex, length: bytesToConsume) else {
            return nil
        }
        return result
    }

    /// Attempts to consume a TLS ServerHello Frame and returns the bytes upon success
    ///
    /// - returns: A `[UInt8]` value containing the `TLS ServerHello`s bytes or `nil` if there wasn't a valid frame available.
    //@inlinable
    public func getTLSServerHello() -> ReadResult {
        guard self.getBytes(at: self.readerIndex, length: 2) == [0x02, 0x00] else { return .invalidFrame }
        guard let length = self.getInteger(at: self.readerIndex + 2, as: UInt16.self) else { return .invalidFrame }
        let bytesToConsume = 4 + Int(length)
        guard let result = self.getBytes(at: self.readerIndex, length: bytesToConsume) else {
            return .needMoreData
        }
        return .success(result)
    }

    public func getTLSServerHelloSlice() -> ByteBuffer? {
        guard self.getBytes(at: self.readerIndex, length: 2) == [0x02, 0x00] else { return nil }
        guard let length = self.getInteger(at: self.readerIndex + 2, as: UInt16.self) else { return nil }
        let bytesToConsume = 4 + Int(length)
        guard let result = self.getSlice(at: self.readerIndex, length: bytesToConsume) else {
            return nil
        }
        return result
    }

    /// Attempts to consume a TLS Encrypted Extensions Frame and returns the bytes upon success
    ///
    /// - returns: A `[UInt8]` value containing the `TLS Encrypted Extension`s bytes or `nil` if there wasn't a valid frame available.
    //@inlinable
    public func getTLSEncryptedExtensions() -> ReadResult {
        guard self.getBytes(at: self.readerIndex, length: 2) == [0x08, 0x00] else { return .invalidFrame }
        guard let length = self.getInteger(at: self.readerIndex + 2, as: UInt16.self) else { return .invalidFrame }
        let bytesToConsume = 4 + Int(length)
        guard let result = self.getBytes(at: self.readerIndex, length: bytesToConsume) else {
            return .needMoreData
        }
        return .success(result)
    }

    public func getTLSEncryptedExtensionsSlice() -> ByteBuffer? {
        guard self.getBytes(at: self.readerIndex, length: 2) == [0x08, 0x00] else { return nil }
        guard let length = self.getInteger(at: self.readerIndex + 2, as: UInt16.self) else { return nil }
        let bytesToConsume = 4 + Int(length)
        guard let result = self.getSlice(at: self.readerIndex, length: bytesToConsume) else {
            return nil
        }
        return result
    }

    /// Attempts to consume a TLS Certificate Frame and returns the bytes upon success
    ///
    /// - returns: A `[UInt8]` value containing the `TLS Certificate`s bytes or `nil` if there wasn't a valid frame available.
    //@inlinable
    public func getTLSCertificate() -> ReadResult {
        guard self.getBytes(at: self.readerIndex, length: 2) == [0x0b, 0x00] else { return .invalidFrame }
        guard let length = self.getInteger(at: self.readerIndex + 2, as: UInt16.self) else { return .invalidFrame }
        let bytesToConsume = 4 + Int(length)
        guard let result = self.getBytes(at: self.readerIndex, length: bytesToConsume) else {
            return .needMoreData
        }
        return .success(result)
    }

    /// Attempts to consume a TLS Certificate Verify Frame and returns the bytes upon success
    ///
    /// - returns: A `[UInt8]` value containing the `TLS Certificate Verify`s bytes or `nil` if there wasn't a valid frame available.
    //@inlinable
    public func getTLSCertificateVerify() -> ReadResult {
        guard self.getBytes(at: self.readerIndex, length: 2) == [0x0f, 0x00] else { return .invalidFrame }
        guard let length = self.getInteger(at: self.readerIndex + 2, as: UInt16.self) else { return .invalidFrame }
        let bytesToConsume = 4 + Int(length)
        guard let result = self.getBytes(at: self.readerIndex, length: bytesToConsume) else {
            return .needMoreData
        }
        return .success(result)
    }

    /// Attempts to consume a TLS Certificate Verify Frame and returns the bytes upon success
    ///
    /// - returns: A `[UInt8]` value containing the `TLS Certificate Verify`s bytes or `nil` if there wasn't a valid frame available.
    //@inlinable
    public func getTLSHandshakeFinished() -> ReadResult {
        guard self.getBytes(at: self.readerIndex, length: 2) == [0x14, 0x00] else { return .invalidFrame }
        guard let length = self.getInteger(at: self.readerIndex + 2, as: UInt16.self) else { return .invalidFrame }
        let bytesToConsume = 4 + Int(length)
        guard let result = self.getBytes(at: self.readerIndex, length: bytesToConsume) else {
            return .needMoreData
        }
        return .success(result)
    }

    public func getQuicCryptoFrameContents() -> [UInt8]? {
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

    //    // https://www.rfc-editor.org/rfc/rfc9000.html#name-sample-variable-length-inte
    //    func readQuicVarInt() -> (bytesRead: Int, value: UInt64)? {
    //
    //      // first two bits of the first byte.
    //      guard self.count >= 1 else { return nil }
    //      var v = UInt64(self[startIndex])
    //      let prefix = v >> 6
    //      let length = (1 << prefix)
    //
    //      guard self.count >= length else { return nil }
    //
    //      // Once the length is known, remove these bits and read any remaining bytes.
    //      v = v & 0x3f
    //      for i in 1..<length {
    //        v = (v << 8) + UInt64(self[startIndex + i])
    //      }
    //
    //      return (length, v)
    //    }

    //  mutating func consumeQuicVarIntLengthPrefixedData() -> (value: UInt64, bytes: [UInt8]) {
    //    if let varInt = self.consumeQuicVarInt() {
    //      let bytes = Array(self[0..<Int(varInt)])
    //      self = Array(self[Int(varInt)...])
    //      return (value: varInt, bytes: bytes)
    //    } else {
    //      return (value: 0, bytes: [])
    //    }
    //  }

    //  mutating func consumeQuicVarInt() -> UInt64? {
    //    // first two bits of the first byte.
    //    guard self.count >= 1 else { return nil }
    //    var v = UInt64(self[0])
    //    let prefix = v >> 6
    //    let length = (1 << prefix)
    //
    //    guard self.count >= length else { return nil }
    //
    //    // Once the length is known, remove these bits and read any remaining bytes.
    //    v = v & 0x3f
    //    for i in 1..<length {
    //      v = (v << 8) + UInt64(self[i])
    //    }
    //
    //    self = Array(self[length...])
    //
    //    return v
    //  }
}

extension ByteBuffer {
    /// Reads / Consumes Zero Byte Padding from the head of the ByteBuffer
    ///
    /// - returns: The number of Zero byte Padding frames that were consumed
    //@inlinable
    @discardableResult
    mutating func readPaddingFrame() -> Int {
        //print("Attempting to remove padding frame:")
        //print(self.readableBytesView.hexString)
        if let endIndex = self.readableBytesView[self.readerIndex...].firstIndex(where: { $0 != 0x00 }) {
            self.moveReaderIndex(forwardBy: endIndex - self.readerIndex)
            return endIndex - self.readerIndex
        } else {
            let paddingCount = self.readableBytes
            self.moveReaderIndex(forwardBy: self.readableBytes)
            return paddingCount
        }
    }

    /// Reads a Ping Frame
    ///
    /// - returns: A `Ping` frame deserialized from this `ByteBuffer` or `nil` if there isn't a complete / valid Ping frame present
    //@inlinable
    mutating func readPingFrame() -> Frames.Ping? {
        return self.rewindReaderOnNil { `self` -> Frames.Ping? in
            guard let type = self.readBytes(length: 1)?.first, type == Frames.Ping.type else { return nil }

            return Frames.Ping()
        }
    }

    /// Reads an ACK Frame
    ///
    /// - returns: A `ACK` frame deserialized from this `ByteBuffer` or `nil` if there isn't a complete / valid ACK frame present
    //@inlinable
    mutating func readACKFrame() -> Frames.ACK? {
        return self.rewindReaderOnNil { `self` -> Frames.ACK? in
            guard let type = self.readBytes(length: 1)?.first else { return nil }
            guard type == 0x02 || type == 0x03 else { return nil }
            guard let largestAcked = self.readQuicVarInt() else { return nil }
            guard let ackDelay = self.readQuicVarInt() else { return nil }
            guard let ackRangeCount = self.readQuicVarInt() else { return nil }
            guard let firstAckRange = self.readQuicVarInt() else { return nil }

            var ackRanges: [Frames.ACK.ACKRange] = []
            for _ in 0..<ackRangeCount {
                guard let gap = self.readQuicVarInt() else { return nil }
                guard let range = self.readQuicVarInt() else { return nil }
                ackRanges.append(
                    Frames.ACK.ACKRange(
                        gap: VarInt(integerLiteral: gap),
                        rangeLength: VarInt(integerLiteral: range)
                    )
                )
            }

            let ecnCounts: Frames.ACK.ECNCounts?
            if type == 0x03 {
                guard let ect0 = self.readQuicVarInt() else { return nil }
                guard let ect1 = self.readQuicVarInt() else { return nil }
                guard let ecnCE = self.readQuicVarInt() else { return nil }
                ecnCounts = Frames.ACK.ECNCounts(
                    ect0: VarInt(integerLiteral: ect0),
                    ect1: VarInt(integerLiteral: ect1),
                    ecnCE: VarInt(integerLiteral: ecnCE)
                )
            } else {
                ecnCounts = nil
            }

            return Frames.ACK(
                largestAcknowledged: VarInt(integerLiteral: largestAcked),
                delay: VarInt(integerLiteral: ackDelay),
                firstAckRange: VarInt(integerLiteral: firstAckRange),
                ranges: ackRanges,
                ecnCounts: ecnCounts
            )
        }
    }

    /// Reads a StopSending Frame
    ///
    /// - returns: A `StopSending` frame deserialized from this `ByteBuffer` or `nil` if there isn't a complete / valid StopSending frame present
    //@inlinable
    mutating func readStopSendingFrame() -> Frames.StopSending? {
        return self.rewindReaderOnNil { `self` -> Frames.StopSending? in
            guard let type = self.readBytes(length: 1)?.first, type == Frames.StopSending.type else { return nil }
            guard let streamID = self.readQuicVarInt() else { return nil }
            guard let appError = self.readQuicVarInt() else { return nil }

            return Frames.StopSending(
                streamID: StreamID(rawValue: VarInt(integerLiteral: streamID)),
                applicationProtocolErrorCode: VarInt(integerLiteral: appError)
            )
        }
    }

    /// Reads a Crypto Frame
    ///
    /// - returns: A `Crypto` frame deserialized from this `ByteBuffer` or `nil` if there isn't a complete / valid Crypto frame present
    //@inlinable
    mutating func readCryptoFrame() -> Frames.Crypto? {
        return self.rewindReaderOnNil { `self` -> Frames.Crypto? in
            guard let type = self.readBytes(length: 1)?.first, type == Frames.Crypto.type else { return nil }
            guard let offset = self.readQuicVarInt() else { return nil }
            guard let length = self.readQuicVarInt() else { return nil }
            guard let data = self.readBytes(length: Int(length)) else { return nil }

            return Frames.Crypto(
                offset: VarInt(integerLiteral: offset),
                data: data
            )
        }
    }

    /// Reads a NewToken Frame
    ///
    /// - returns: A `NewToken` frame deserialized from this `ByteBuffer` or `nil` if there isn't a complete / valid NewToken frame present
    //@inlinable
    mutating func readNewTokenFrame() -> Frames.NewToken? {
        return self.rewindReaderOnNil { `self` -> Frames.NewToken? in
            guard let type = self.readBytes(length: 1)?.first, type == Frames.NewToken.type else { return nil }
            guard let length = self.readQuicVarInt() else { return nil }
            guard let token = self.readBytes(length: Int(length)) else { return nil }

            return Frames.NewToken(token: token)
        }
    }

    /// Reads a Stream Frame
    ///
    /// - returns: A `Stream` frame deserialized from this `ByteBuffer` or `nil` if there isn't a complete / valid Stream frame present
    //@inlinable
    mutating func readStreamFrame() -> Frames.Stream? {
        return self.rewindReaderOnNil { `self` -> Frames.Stream? in
            guard let firstByte = self.readBytes(length: 1)?.first else { return nil }
            guard let streamID = self.readQuicVarInt() else { return nil }

            let offset: VarInt?
            if (firstByte & 0x04) == 4 {
                guard let off = self.readQuicVarInt() else { return nil }
                offset = VarInt(integerLiteral: off)
            } else { offset = nil }

            let length: VarInt?
            if (firstByte & 0x02) == 2 {
                guard let len = self.readQuicVarInt() else { return nil }
                length = VarInt(integerLiteral: len)
            } else { length = nil }

            let fin = (firstByte & 0x01) == 1

            let payload: ByteBuffer
            if let length {
                guard let p = self.readSlice(length: Int(length.rawValue)) else { return nil }
                payload = p
            } else {
                guard let p = self.readSlice(length: self.readableBytes) else { return nil }
                payload = p
            }

            return Frames.Stream(
                streamID: StreamID(rawValue: VarInt(integerLiteral: streamID)),
                offset: offset,
                length: length,
                fin: fin,
                data: payload
            )
        }
    }

    /// Reads a ResetStream Frame
    ///
    /// - returns: A `ResetStream` frame deserialized from this `ByteBuffer` or `nil` if there isn't a complete / valid ResetStream frame present
    //@inlinable
    mutating func readResetStreamFrame() -> Frames.ResetStream? {
        return self.rewindReaderOnNil { `self` -> Frames.ResetStream? in
            guard let type = self.readBytes(length: 1)?.first, type == Frames.ResetStream.type else { return nil }
            guard let streamID = self.readQuicVarInt() else { return nil }
            guard let appError = self.readQuicVarInt() else { return nil }
            guard let finalSize = self.readQuicVarInt() else { return nil }

            return Frames.ResetStream(
                streamID: StreamID(rawValue: VarInt(integerLiteral: streamID)),
                applicationProtocolErrorCode: VarInt(integerLiteral: appError),
                finalSize: VarInt(integerLiteral: finalSize)
            )
        }
    }

    /// Reads a MaxData Frame
    ///
    /// - returns: A `MaxData` frame deserialized from this `ByteBuffer` or `nil` if there isn't a complete / valid MaxData frame present
    //@inlinable
    mutating func readMaxDataFrame() -> Frames.MaxData? {
        return self.rewindReaderOnNil { `self` -> Frames.MaxData? in
            guard let type = self.readBytes(length: 1)?.first, type == Frames.MaxData.type else { return nil }
            guard let maxData = self.readQuicVarInt() else { return nil }

            return Frames.MaxData(maximumData: VarInt(integerLiteral: maxData))
        }
    }

    /// Reads a MaxStreamData Frame
    ///
    /// - returns: A `MaxStreamData` frame deserialized from this `ByteBuffer` or `nil` if there isn't a complete / valid MaxStreamData frame present
    //@inlinable
    mutating func readMaxStreamDataFrame() -> Frames.MaxStreamData? {
        return self.rewindReaderOnNil { `self` -> Frames.MaxStreamData? in
            guard let type = self.readBytes(length: 1)?.first, type == Frames.MaxStreamData.type else { return nil }
            guard let streamID = self.readQuicVarInt() else { return nil }
            guard let maxStreamData = self.readQuicVarInt() else { return nil }

            return Frames.MaxStreamData(
                streamID: StreamID(rawValue: VarInt(integerLiteral: streamID)),
                maximumStreamData: VarInt(integerLiteral: maxStreamData)
            )
        }
    }

    /// Reads a MaxStreams Frame
    ///
    /// - returns: A `MaxStreams` frame deserialized from this `ByteBuffer` or `nil` if there isn't a complete / valid MaxStreams frame present
    //@inlinable
    mutating func readMaxStreamsFrame() -> Frames.MaxStreams? {
        return self.rewindReaderOnNil { `self` -> Frames.MaxStreams? in
            guard let type = self.readBytes(length: 1)?.first else { return nil }
            guard let streamType = Frames.MaxStreams.StreamType(rawValue: type) else { return nil }
            guard let maxStreams = self.readQuicVarInt() else { return nil }

            return Frames.MaxStreams(
                streamType: streamType,
                maximumStreams: VarInt(integerLiteral: maxStreams)
            )
        }
    }

    /// Reads a DataBlocked Frame
    ///
    /// - returns: A `DataBlocked` frame deserialized from this `ByteBuffer` or `nil` if there isn't a complete / valid DataBlocked frame present
    //@inlinable
    mutating func readDataBlockedFrame() -> Frames.DataBlocked? {
        return self.rewindReaderOnNil { `self` -> Frames.DataBlocked? in
            guard let type = self.readBytes(length: 1)?.first, type == Frames.DataBlocked.type else { return nil }
            guard let maxData = self.readQuicVarInt() else { return nil }

            return Frames.DataBlocked(maximumData: VarInt(integerLiteral: maxData))
        }
    }

    /// Reads a StreamDataBlocked Frame
    ///
    /// - returns: A `StreamDataBlocked` frame deserialized from this `ByteBuffer` or `nil` if there isn't a complete / valid StreamDataBlocked frame present
    //@inlinable
    mutating func readStreamDataBlockedFrame() -> Frames.StreamDataBlocked? {
        return self.rewindReaderOnNil { `self` -> Frames.StreamDataBlocked? in
            guard let type = self.readBytes(length: 1)?.first, type == Frames.StreamDataBlocked.type else { return nil }
            guard let streamID = self.readQuicVarInt() else { return nil }
            guard let maxStreamData = self.readQuicVarInt() else { return nil }

            return Frames.StreamDataBlocked(
                streamID: StreamID(rawValue: VarInt(integerLiteral: streamID)),
                maximumStreamData: VarInt(integerLiteral: maxStreamData)
            )
        }
    }

    /// Reads a StreamsBlocked Frame
    ///
    /// - returns: A `StreamsBlocked` frame deserialized from this `ByteBuffer` or `nil` if there isn't a complete / valid StreamsBlocked frame present
    //@inlinable
    mutating func readStreamsBlockedFrame() -> Frames.StreamsBlocked? {
        return self.rewindReaderOnNil { `self` -> Frames.StreamsBlocked? in
            guard let type = self.readBytes(length: 1)?.first else { return nil }
            guard let streamType = Frames.StreamsBlocked.StreamType(rawValue: type) else { return nil }
            guard let maxStreams = self.readQuicVarInt() else { return nil }

            return Frames.StreamsBlocked(
                streamType: streamType,
                maximumStreams: VarInt(integerLiteral: maxStreams)
            )
        }
    }

    /// Reads a NewConnectionID Frame
    ///
    /// - returns: A `NewConnectionID` frame deserialized from this `ByteBuffer` or `nil` if there isn't a complete / valid NewConnectionID frame present
    //@inlinable
    mutating func readNewConnectionIDFrame() -> Frames.NewConnectionID? {
        return self.rewindReaderOnNil { `self` -> Frames.NewConnectionID? in
            guard let type = self.readBytes(length: 1)?.first, type == Frames.NewConnectionID.type else { return nil }
            guard let seqNum = self.readQuicVarInt() else { return nil }
            guard let retirePT = self.readQuicVarInt() else { return nil }
            guard let length = self.readInteger(endianness: .big, as: UInt8.self), length >= 1, length <= 20 else { return nil }
            guard let cid = self.readBytes(length: Int(length)) else { return nil }
            guard let srt = self.readBytes(length: 16) else { return nil }

            return Frames.NewConnectionID(
                sequenceNumber: VarInt(integerLiteral: seqNum),
                retirePriorTo: VarInt(integerLiteral: retirePT),
                connectionID: ConnectionID(with: cid),
                statelessResetToken: srt
            )
        }
    }

    /// Reads a RetireConnectionID Frame
    ///
    /// - returns: A `RetireConnectionID` frame deserialized from this `ByteBuffer` or `nil` if there isn't a complete / valid RetireConnectionID frame present
    //@inlinable
    mutating func readRetireConnectionIDFrame() -> Frames.RetireConnectionID? {
        return self.rewindReaderOnNil { `self` -> Frames.RetireConnectionID? in
            guard let type = self.readBytes(length: 1)?.first, type == Frames.RetireConnectionID.type else { return nil }
            guard let seqNum = self.readQuicVarInt() else { return nil }

            return Frames.RetireConnectionID(sequenceNumber: VarInt(integerLiteral: seqNum))
        }
    }

    /// Reads a PathChallenge Frame
    ///
    /// - returns: A `PathChallenge` frame deserialized from this `ByteBuffer` or `nil` if there isn't a complete / valid PathChallenge frame present
    //@inlinable
    mutating func readPathChallengeFrame() -> Frames.PathChallenge? {
        return self.rewindReaderOnNil { `self` -> Frames.PathChallenge? in
            guard let type = self.readBytes(length: 1)?.first, type == Frames.PathChallenge.type else { return nil }
            guard let data = self.readBytes(length: 8) else { return nil }

            return Frames.PathChallenge(data: data)
        }
    }

    /// Reads a PathResponse Frame
    ///
    /// - returns: A `PathResponse` frame deserialized from this `ByteBuffer` or `nil` if there isn't a complete / valid PathResponse frame present
    //@inlinable
    mutating func readPathResponseFrame() -> Frames.PathResponse? {
        return self.rewindReaderOnNil { `self` -> Frames.PathResponse? in
            guard let type = self.readBytes(length: 1)?.first, type == Frames.PathResponse.type else { return nil }
            guard let data = self.readBytes(length: 8) else { return nil }

            return Frames.PathResponse(data: data)
        }
    }

    /// Reads a ConnectionClose Frame
    ///
    /// - returns: A `ConnectionClose` frame deserialized from this `ByteBuffer` or `nil` if there isn't a complete / valid ConnectionClose frame present
    //@inlinable
    mutating func readConnectionCloseFrame() -> Frames.ConnectionClose? {
        return self.rewindReaderOnNil { `self` -> Frames.ConnectionClose? in
            guard let type = self.readBytes(length: 1)?.first else { return nil }
            guard let closeType = Frames.ConnectionClose.CloseType(rawValue: type) else { return nil }
            guard let errorCode = self.readQuicVarInt() else { return nil }

            let frameType: VarInt?
            if closeType == .quic {
                guard let fType = self.readQuicVarInt() else { return nil }
                frameType = VarInt(integerLiteral: fType)
            } else { frameType = nil }

            guard let reasonPhraseLength = self.readQuicVarInt() else { return nil }
            guard let reasonPhrase = self.readString(length: Int(reasonPhraseLength)) else { return nil }

            return Frames.ConnectionClose(
                closeType: closeType,
                errorCode: VarInt(integerLiteral: errorCode),
                frameType: frameType,
                reasonPhrase: reasonPhrase
            )
        }
    }

    /// Reads a HandshakeDone Frame
    ///
    /// - returns: A `HandshakeDone` frame deserialized from this `ByteBuffer` or `nil` if there isn't a complete / valid HandshakeDone frame present
    //@inlinable
    mutating func readHandshakeDoneFrame() -> Frames.HandshakeDone? {
        return self.rewindReaderOnNil { `self` -> Frames.HandshakeDone? in
            guard let type = self.readBytes(length: 1)?.first, type == Frames.HandshakeDone.type else { return nil }

            return Frames.HandshakeDone()
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

extension ByteBuffer {

    internal mutating func parsePayloadIntoFrames() throws -> (frames: [any Frame], leftoverBytes: ByteBuffer?) {
        let result = self.rewindReaderOnNil { `self` -> (frames: [any Frame], leftoverBytes: ByteBuffer?)? in
            var frames: [any Frame] = []
            var leftoverBytes: ByteBuffer?

            readLoop: while self.readableBytes > 0 {

                guard let firstByte = self.getBytes(at: self.readerIndex, length: 1)?.first else { break readLoop }
                switch firstByte {
                    case Frames.Padding.type: //0x00
                        self.readPaddingFrame()
                    //frames.append(Frames.Padding(length: padding))
                    case Frames.Ping.type: // 0x01
                        guard let ping = self.readPingFrame() else { break readLoop }
                        frames.append(ping)
                    case 0x02...0x03: // ACK Frames
                        guard let ack = self.readACKFrame() else { break readLoop }
                        frames.append(ack)
                    case Frames.ResetStream.type: // 0x04
                        guard let rs = self.readResetStreamFrame() else { break readLoop }
                        frames.append(rs)
                    case Frames.StopSending.type: //0x05
                        guard let ss = self.readStopSendingFrame() else { break readLoop }
                        frames.append(ss)
                    case Frames.Crypto.type: // 0x06
                        guard let crypto = self.readCryptoFrame() else { break readLoop }
                        frames.append(crypto)
                    case Frames.NewToken.type: // 0x07
                        guard let nt = self.readNewTokenFrame() else { break readLoop }
                        frames.append(nt)
                    case 0x08...0x0f: // Stream Frames
                        guard let streamFrame = self.readStreamFrame() else { break readLoop }
                        frames.append(streamFrame)
                    case Frames.MaxData.type: //0x10
                        guard let maxData = self.readMaxDataFrame() else { break readLoop }
                        frames.append(maxData)
                    case Frames.MaxStreamData.type: //0x11
                        guard let maxStreamData = self.readMaxStreamDataFrame() else { break readLoop }
                        frames.append(maxStreamData)
                    case 0x12...0x13: //Max Streams Frame
                        guard let maxStreams = self.readMaxStreamsFrame() else { break readLoop }
                        frames.append(maxStreams)
                    case Frames.DataBlocked.type: //0x14
                        guard let dataBlocked = self.readDataBlockedFrame() else { break readLoop }
                        frames.append(dataBlocked)
                    case Frames.StreamDataBlocked.type: //0x15
                        guard let streamDataBlocked = self.readStreamDataBlockedFrame() else { break readLoop }
                        frames.append(streamDataBlocked)
                    case 0x16...0x17: //StreamsBlocked Frame
                        guard let streamsBlocked = self.readStreamsBlockedFrame() else { break readLoop }
                        frames.append(streamsBlocked)
                    case Frames.NewConnectionID.type: //0x18
                        guard let ncid = self.readNewConnectionIDFrame() else { break readLoop }
                        frames.append(ncid)
                    case Frames.RetireConnectionID.type: //0x19
                        guard let retireID = self.readRetireConnectionIDFrame() else { break readLoop }
                        frames.append(retireID)
                    case Frames.PathChallenge.type: //0x1a
                        guard let pathChallenge = self.readPathChallengeFrame() else { break readLoop }
                        frames.append(pathChallenge)
                    case Frames.PathResponse.type: //0x1b
                        guard let pathResponse = self.readPathResponseFrame() else { break readLoop }
                        frames.append(pathResponse)
                    case 0x1c...0x1d: //ConnectionClose Frame
                        guard let conClose = self.readConnectionCloseFrame() else { break readLoop }
                        frames.append(conClose)
                    case Frames.HandshakeDone.type: // 0x1e
                        guard let hd = self.readHandshakeDoneFrame() else { break readLoop }
                        frames.append(hd)
                    default:
                        print("TODO::Handle Frame Type: \([firstByte].hexString)")
                        leftoverBytes = self.readSlice(length: self.readableBytes)
                        break readLoop
                }
            }
            if self.readableBytes != 0 { return nil }

            return (frames: frames, leftoverBytes: leftoverBytes)
        }

        guard let result else { throw Errors.InvalidFrame }

        return result
    }
}

extension Array where Element == UInt8 {
    internal func parsePayloadIntoFrames() throws -> (frames: [any Frame], leftoverBytes: [UInt8]?) {
        var buf = ByteBuffer(bytes: self)
        let res = try buf.parsePayloadIntoFrames()
        if let leftoverBytes = res.leftoverBytes {
            return (frames: res.frames, leftoverBytes: Array(leftoverBytes.readableBytesView))
        }
        return (frames: res.frames, leftoverBytes: nil)
    }
}
