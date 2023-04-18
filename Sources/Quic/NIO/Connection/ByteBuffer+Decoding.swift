

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
    
    mutating func writeConnectionID(_ cid:ConnectionID) {
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
    
    mutating func writeVersion(_ version:Version) {
        self.writeQuicVarIntLengthPrefixedBytes(version.withUnsafeBytes { Array($0) })
    }
}

/// PacketNumberOffset
extension ByteBuffer {
    func getLongHeaderPacketNumberOffset(at initialOffset:Int, isInitial:Bool) throws -> (packetLength: UInt64, packetNumberOffset: Int) {
        // Header Byte and 4 Byte Version
        var offset = initialOffset + 5
        // Read DCID
        offset += try varIntLengthPrefixedByteCount(at: offset)
        // Read SCID
        offset += try varIntLengthPrefixedByteCount(at: offset)
        if isInitial {
            // Read the Token
            offset += try varIntLengthPrefixedByteCount(at: offset)
        }
        // Read the packet length VarInt
        guard let varInt = self.getQuicVarInt(at: offset) else { throw Errors.InvalidPacket }
        return (packetLength: varInt.value, packetNumberOffset: offset + varInt.length)
    }
    
    private func varIntLengthPrefixedByteCount(at offset:Int) throws -> Int {
        guard let varInt = self.getQuicVarInt(at: offset) else { throw Errors.InvalidPacket }
        return varInt.length + Int(varInt.value)
    }
}


extension ByteBuffer {
    // We should be directly mutating the buffer
    mutating func unprotectLongHeader(at headerOffset:Int, packetNumberOffset:Int, sampleSize:Int, using opener:Opener) throws -> Int {
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
    
    mutating func decryptBytes(at offset:Int, packetLength:Int, headerOffset:Int, packetNumber:[UInt8], using opener: Opener, paddingRemovalStrategy:PaddingRemoval = .doNothing) throws {
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
