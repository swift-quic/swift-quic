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

extension ByteBuffer {
    /// Attempts to consume a TLS ServerHello Frame and returns the bytes upon success
    ///
    /// - returns: A `[UInt8]` value containing the `TLS ServerHello`s bytes or `nil` if there wasn't a valid frame available.
    @inlinable
    mutating func readTLSClientHello() -> ReadResult<[UInt8]> {
        let result = self.getTLSClientHello()
        if case .success(let clientHello) = result {
            self.moveReaderIndex(forwardBy: clientHello.count)
        }
        return result
    }

    /// Attempts to consume a TLS ServerHello Frame and returns the bytes upon success
    ///
    /// - returns: A `[UInt8]` value containing the `TLS ServerHello`s bytes or `nil` if there wasn't a valid frame available.
    @inlinable
    mutating func readTLSServerHello() -> ReadResult<[UInt8]> {
        let result = self.getTLSServerHello()
        if case .success(let serverHello) = result {
            self.moveReaderIndex(forwardBy: serverHello.count)
        }
        return result
    }

    /// Attempts to consume a TLS Encrypted Extensions Frame and returns the bytes upon success
    ///
    /// - returns: A `[UInt8]` value containing the `TLS Encrypted Extension`s bytes or `nil` if there wasn't a valid frame available.
    @inlinable
    mutating func readTLSEncryptedExtensions() -> ReadResult<[UInt8]> {
        let result = self.getTLSEncryptedExtensions()
        if case .success(let encryptedExtensions) = result {
            self.moveReaderIndex(forwardBy: encryptedExtensions.count)
        }
        return result
    }

    /// Attempts to consume a TLS Certificate Frame and returns the bytes upon success
    ///
    /// - returns: A `[UInt8]` value containing the `TLS Certificate`s bytes or `nil` if there wasn't a valid frame available.
    @inlinable
    mutating func readTLSCertificate() -> ReadResult<[UInt8]> {
        let result = self.getTLSCertificate()
        if case .success(let certificate) = result {
            self.moveReaderIndex(forwardBy: certificate.count)
        }
        return result
    }

    /// Attempts to consume a TLS Certificate Verify Frame and returns the bytes upon success
    ///
    /// - returns: A `[UInt8]` value containing the `TLS Certificate Verify`s bytes or `nil` if there wasn't a valid frame available.
    @inlinable
    mutating func readTLSCertificateVerify() -> ReadResult<[UInt8]> {
        let result = self.getTLSCertificateVerify()
        if case .success(let certVerify) = result {
            self.moveReaderIndex(forwardBy: certVerify.count)
        }
        return result
    }

    /// Attempts to consume a TLS Certificate Verify Frame and returns the bytes upon success
    ///
    /// - returns: A `[UInt8]` value containing the `TLS Certificate Verify`s bytes or `nil` if there wasn't a valid frame available.
    @inlinable
    mutating func readTLSHandshakeFinished() -> ReadResult<[UInt8]> {
        let result = self.getTLSHandshakeFinished()
        if case .success(let finished) = result {
            self.moveReaderIndex(forwardBy: finished.count)
        }
        return result
    }

    /// Attempts to get a TLS ClientHello Frame and returns the bytes upon success
    ///
    /// - returns: A `[UInt8]` value containing the `TLS ClientHello`s bytes or `nil` if there wasn't a valid frame available.
    @inlinable
    func getTLSClientHello() -> ReadResult<[UInt8]> {
        return self.getTLS(frame: .clientHello)
    }

    /// Attempts to get a TLS ClientHello Frame and returns the byte buffer slice upon success
    ///
    /// - returns: A `ByteBuffer` value containing the `TLS ClientHello`s slice or `nil` if there wasn't a valid frame available.
    @inlinable
    func getTLSClientHelloSlice() -> ByteBuffer? {
        return self.optionallyUnwraped(self.getTLSSlice(frame: .clientHello))
    }

    /// Attempts to get a TLS ServerHello Frame and returns the bytes upon success
    ///
    /// - returns: A `[UInt8]` value containing the `TLS ServerHello`s bytes or `nil` if there wasn't a valid frame available.
    @inlinable
    func getTLSServerHello() -> ReadResult<[UInt8]> {
        return self.getTLS(frame: .serverHello)
    }

    /// Attempts to get a TLS ServerHello Frame and returns the byte buffer slice upon success
    ///
    /// - returns: A `ByteBuffer` value containing the `TLS ServerHello`s slice or `nil` if there wasn't a valid frame available.
    @inlinable
    func getTLSServerHelloSlice() -> ByteBuffer? {
        return self.optionallyUnwraped(self.getTLSSlice(frame: .serverHello))
    }

    /// Attempts to get a TLS Encrypted Extensions Frame and returns the bytes upon success
    ///
    /// - returns: A `[UInt8]` value containing the `TLS Encrypted Extension`s bytes or `nil` if there wasn't a valid frame available.
    @inlinable
    func getTLSEncryptedExtensions() -> ReadResult<[UInt8]> {
        return self.getTLS(frame: .encryptedExtensions)
    }

    /// Attempts to get a TLS EncryptedExtensions Frame and returns the byte buffer slice upon success
    ///
    /// - returns: A `ByteBuffer` value containing the `TLS EncryptedExtensions`s slice or `nil` if there wasn't a valid frame available.
    @inlinable
    func getTLSEncryptedExtensionsSlice() -> ByteBuffer? {
        return self.optionallyUnwraped(self.getTLSSlice(frame: .encryptedExtensions))
    }

    /// Attempts to get a TLS Certificate Frame and returns the bytes upon success
    ///
    /// - returns: A `[UInt8]` value containing the `TLS Certificate`s bytes or `nil` if there wasn't a valid frame available.
    @inlinable
    func getTLSCertificate() -> ReadResult<[UInt8]> {
        return self.getTLS(frame: .certificate)
    }

    /// Attempts to get a TLS Certificate Verify Frame and returns the bytes upon success
    ///
    /// - returns: A `[UInt8]` value containing the `TLS Certificate Verify`s bytes or `nil` if there wasn't a valid frame available.
    @inlinable
    func getTLSCertificateVerify() -> ReadResult<[UInt8]> {
        return self.getTLS(frame: .certificateVerify)
    }

    /// Attempts to get a TLS Certificate Verify Frame and returns the bytes upon success
    ///
    /// - returns: A `[UInt8]` value containing the `TLS Certificate Verify`s bytes or `nil` if there wasn't a valid frame available.
    @inlinable
    func getTLSHandshakeFinished() -> ReadResult<[UInt8]> {
        return self.getTLS(frame: .finished)
    }

    /// https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.3
    @usableFromInline
    enum TLSFrame: UInt8 {
        case helloRequestRESERVED = 0
        case clientHello = 1
        case serverHello = 2
        case helloVerifyRequestRESERVED = 3
        case newSessionTicket = 4
        case endOfEarlyData = 5
        case helloRetryRequestRESERVED = 6
        case encryptedExtensions = 8
        case certificate = 11
        case serverKeyExchangeRESERVED = 12
        case certificateRequest = 13
        case serverHelloDoneRESERVED = 14
        case certificateVerify = 15
        case clientKeyExchangeRESERVED = 16
        case finished = 20
        case certificateUrlRESERVED = 21
        case certificateStatusRESERVED = 22
        case supplementalDataRESERVED = 23
        case keyUpdate = 24
        case messageHash = 254
    }

    // TODO: The length prefix is technically a UInt24
    @inlinable
    func getTLSFrameHeader(at: Int) -> ReadResult<(TLSFrame, Int)> {
        guard let tag = self.getBytes(at: at, length: 1)?.first else { return .needMoreData }
        guard let type = TLSFrame(rawValue: tag) else { return .invalidFrame }
        guard let length = self.getInteger(at: at + 2, as: UInt16.self) else { return .invalidFrame }
        let bytesToConsume = 4 + Int(length)
        return .success((type, bytesToConsume))
    }

    @inlinable
    func getTLS(frame: TLSFrame) -> ReadResult<[UInt8]> {
        switch self.getTLSFrameHeader(at: self.readerIndex) {
            case .invalidFrame: return .invalidFrame
            case .needMoreData: return .needMoreData
            case .success((let type, let bytesToConsume)):
                guard type == frame else { return .invalidFrame }
                guard let result = self.getBytes(at: self.readerIndex, length: bytesToConsume) else {
                    return .needMoreData
                }
                return .success(result)
        }
    }

    @inlinable
    func getTLSSlice(frame: TLSFrame) -> ReadResult<ByteBuffer> {
        switch self.getTLSFrameHeader(at: self.readerIndex) {
            case .invalidFrame: return .invalidFrame
            case .needMoreData: return .needMoreData
            case .success((let type, let bytesToConsume)):
                guard type == frame else { return .invalidFrame }
                guard let result = self.getSlice(at: self.readerIndex, length: bytesToConsume) else {
                    return .needMoreData
                }
                return .success(result)
        }
    }

    @inlinable
    mutating func readTLS(frame: TLSFrame) -> ReadResult<[UInt8]> {
        let res = self.getTLS(frame: frame)
        if case .success(let r) = res {
            self.moveWriterIndex(forwardBy: r.count)
        }
        return res
    }

    @inlinable
    func getTLSFrame() -> ReadResult<(TLSFrame, [UInt8])> {
        switch self.getTLSFrameHeader(at: self.readerIndex) {
            case .invalidFrame: return .invalidFrame
            case .needMoreData: return .needMoreData
            case .success((let type, let bytesToConsume)):
                guard let result = self.getBytes(at: self.readerIndex, length: bytesToConsume) else {
                    return .needMoreData
                }
                return .success((type, result))
        }
    }

    @inlinable
    func getTLSFrameSlice() -> ReadResult<(TLSFrame, ByteBuffer)> {
        switch self.getTLSFrameHeader(at: self.readerIndex) {
            case .invalidFrame: return .invalidFrame
            case .needMoreData: return .needMoreData
            case .success((let type, let bytesToConsume)):
                guard let result = self.getSlice(at: self.readerIndex, length: bytesToConsume) else {
                    return .needMoreData
                }
                return .success((type, result))
        }
    }

    @inlinable
    mutating func readTLSFrame() -> ReadResult<(TLSFrame, [UInt8])> {
        let res = self.getTLSFrame()
        if case .success(let r) = res {
            self.moveWriterIndex(forwardBy: r.1.count)
        }
        return res
    }
}
