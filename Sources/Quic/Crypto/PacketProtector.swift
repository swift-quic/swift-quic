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

import Crypto
import Foundation
import NIOCore

struct Sealer {
    internal let encryptor: any QBlockCipher
    internal let headerProtector: HeaderProtector

    public func applyHeaderProtection<SAMPLE, HEADER>(sample: SAMPLE, hdrBytes: inout HEADER, packetNumberOffset: Int) throws where SAMPLE: ContiguousBytes, HEADER: ContiguousBytes {
        try self.headerProtector.applyMask(sample: sample, headerBytes: &hdrBytes, packetNumberOffset: packetNumberOffset)
    }

    public func encryptPayload(_ payload: any DataProtocol, packetNumber: [UInt8], authenticatingData: any DataProtocol) throws -> [UInt8] {
        try self.encryptor.seal(message: payload, packetNumber: packetNumber, authenticatingData: authenticatingData).ciphertext.withUnsafeBytes { Array($0) }
    }
}

struct Opener {
    internal let decrypter: any QBlockCipher
    internal let headerProtector: HeaderProtector

    public func removeHeaderProtection<SAMPLE, HEADER>(sample: SAMPLE, hdrBytes: inout HEADER, packetNumberOffset: Int) throws where SAMPLE: ContiguousBytes, HEADER: ContiguousBytes {
        try self.headerProtector.removeMask(sample: sample, headerBytes: &hdrBytes, packetNumberOffset: packetNumberOffset)
    }

    public func decryptPayload(cipherText: ContiguousBytes, packetNumber: [UInt8], unprotectedHeaderBytes: any DataProtocol) throws -> [UInt8] {
        try self.decrypter.open(cipherText, packetNumber: packetNumber, authenticatingData: unprotectedHeaderBytes)
    }
}

/// PacketProtector provides a simple interface for opening and sealing, inbound and outbound, packets for a given Epoch.
struct PacketProtector {
    let epoch: Epoch
    let version: Version
    private(set) var opener: Opener?
    private(set) var sealer: Sealer?

    /// This method allows ups to update a PacketProtecter with new keys as they are made available by our TLS instance.
    internal mutating func installKeySet(suite: CipherSuite, secret: [UInt8], for mode: EndpointRole, ourPerspective perspective: EndpointRole) throws {
        switch (perspective, mode) {
            case (.client, .client),
                 (.server, .server):
                guard self.sealer == nil else { print("\(self.epoch)::Our Sealer is Already Installed"); throw Errors.Crypto(0) }
                self.sealer = try self.version.newSealer(mySecret: SymmetricKey(data: secret), suite: suite)

            case (.server, .client),
                 (.client, .server):
                guard self.opener == nil else { print("\(self.epoch)::Peers Opener is Already Installed"); throw Errors.Crypto(0) }
                self.opener = try self.version.newOpener(otherSecret: SymmetricKey(data: secret), suite: suite)
        }
    }

    internal mutating func dropKeys() {
        print("PacketProtector::\(self.epoch)::Dropping Keys")
        self.opener = nil
        self.sealer = nil
    }

    func applyHeaderProtection<SAMPLE, HEADER>(sample: SAMPLE, headerBytes: inout HEADER, packetNumberOffset: Int) throws where SAMPLE: ContiguousBytes, HEADER: ContiguousBytes {
        guard let sealer = self.sealer else { throw Errors.Crypto(0) }
        try sealer.headerProtector.applyMask(sample: sample, headerBytes: &headerBytes, packetNumberOffset: packetNumberOffset)
    }

    func removeHeaderProtection<SAMPLE, HEADER>(sample: SAMPLE, headerBytes: inout HEADER, packetNumberOffset: Int) throws where SAMPLE: ContiguousBytes, HEADER: ContiguousBytes {
        guard let opener = self.opener else { throw Errors.Crypto(0) }
        try opener.headerProtector.removeMask(sample: sample, headerBytes: &headerBytes, packetNumberOffset: packetNumberOffset)
    }

    func encryptPayload<M, A>(message: M, packetNumber: [UInt8], authenticatingData: A) throws -> QSealedBox where M: DataProtocol, A: DataProtocol {
        guard let sealer = self.sealer else { throw Errors.Crypto(0) }
        return try sealer.encryptor.seal(message: message, packetNumber: packetNumber, authenticatingData: authenticatingData)
    }

    func decryptPayload<A>(_ cipherText: ContiguousBytes, packetNumber: [UInt8], authenticatingData authenticatedData: A) throws -> [UInt8] where A: DataProtocol {
        guard let opener = self.opener else { throw Errors.Crypto(0) }
        return try opener.decrypter.open(cipherText, packetNumber: packetNumber, authenticatingData: authenticatedData)
    }

    /// Provided the bytes representing an encrypted packet, this method attempts to decrypt the payload, and remove the header protection.
    // TODO: Replace this with a proper decoding scheme
    func open(bytes: [UInt8], packetNumberOffset pno: Int) throws -> (header: [UInt8], payload: [UInt8]) {
        let sampleOffset = pno + 4
        let sample = Array(bytes[sampleOffset..<sampleOffset + 16])
        //print("Sample: \(sample.hexString)")
        var hb = Array(bytes[..<(pno + 4)])
        //print("Masked Header: \(hb.hexString)")
        try self.removeHeaderProtection(sample: sample, headerBytes: &hb, packetNumberOffset: pno)
        //print("Unmasked Header: \(hb.hexString)")

        let pnl = PacketNumberLength(rawValue: hb.first! & PacketNumberLength.mask)!
        //print("PacketNumberLength: \(pnl)")

        let ct = Array(bytes[(pno + pnl.bytesToRead)...])
        let unprotectedHeader = hb //Array(hb.dropLast(4 - pnl.bytesToRead))
        let packetNumber = Array(unprotectedHeader.suffix(pnl.bytesToRead))
        //print("PacketNumber: \(packetNumber.hexString)")
        //print("Unprotected Header: \(unprotectedHeader.hexString)")

        //print("Cipher Text: \(ct.hexString)")
        let decryptedPayload = try decryptPayload(ct, packetNumber: packetNumber, authenticatingData: unprotectedHeader)

        //print("Decrypted Payload:")
        //print(Array(decryptedPayload.drop(while: { $0 == 0 })).hexString)
        return (header: unprotectedHeader, payload: decryptedPayload)
    }
}

extension Version {

    public func newInitialAEAD(connectionID: ConnectionID, perspective: EndpointRole) throws -> PacketProtector {
        let initialTrafficSecrets = try computeInitialSecrets(connID: connectionID, v: self)

        let mySecret: SymmetricKey
        let otherSecret: SymmetricKey
        if perspective == .client {
            mySecret = initialTrafficSecrets.clientSecret
            otherSecret = initialTrafficSecrets.serverSecret
        } else {
            mySecret = initialTrafficSecrets.serverSecret
            otherSecret = initialTrafficSecrets.clientSecret
        }

        return try self.newAEAD(mySecret: mySecret, otherSecret: otherSecret, perspective: perspective, suite: .AESGCM128_SHA256, epoch: .Initial)
    }

    public func newAEAD(clientSecret: [UInt8], serverSecret: [UInt8], perspective: EndpointRole, suite: CipherSuite, epoch: Epoch) throws -> PacketProtector {
        let mySecret: SymmetricKey
        let otherSecret: SymmetricKey
        if perspective == .client {
            mySecret = SymmetricKey(data: clientSecret)
            otherSecret = SymmetricKey(data: serverSecret)
        } else {
            mySecret = SymmetricKey(data: serverSecret)
            otherSecret = SymmetricKey(data: clientSecret)
        }

        return try self.newAEAD(mySecret: mySecret, otherSecret: otherSecret, perspective: perspective, suite: suite, epoch: epoch)
    }

    internal func newAEAD(mySecret: SymmetricKey, otherSecret: SymmetricKey, perspective: EndpointRole, suite: CipherSuite, epoch: Epoch) throws -> PacketProtector {
        let (myKey, myIV) = try computeKeyAndIV(secret: mySecret, v: self, cipherSuite: suite)
        let (otherKey, otherIV) = try computeKeyAndIV(secret: otherSecret, v: self, cipherSuite: suite)

        return PacketProtector(
            epoch: epoch,
            version: self,
            opener: Opener(
                decrypter: try suite.newBlockCipher(key: otherKey, iv: otherIV),
                headerProtector: try suite.newHeaderProtector(trafficSecret: otherSecret, version: self)
            ),
            sealer: Sealer(
                encryptor: try suite.newBlockCipher(key: myKey, iv: myIV),
                headerProtector: try suite.newHeaderProtector(trafficSecret: mySecret, version: self)
            )
        )
    }

    internal func newOpener(otherSecret: SymmetricKey, suite: CipherSuite) throws -> Opener {
        let (otherKey, otherIV) = try computeKeyAndIV(secret: otherSecret, v: self, cipherSuite: suite)
        return Opener(
            decrypter: try suite.newBlockCipher(key: otherKey, iv: otherIV),
            headerProtector: try suite.newHeaderProtector(trafficSecret: otherSecret, version: self)
        )
    }

    internal func newSealer(mySecret: SymmetricKey, suite: CipherSuite) throws -> Sealer {
        let (myKey, myIV) = try computeKeyAndIV(secret: mySecret, v: self, cipherSuite: suite)
        return Sealer(
            encryptor: try suite.newBlockCipher(key: myKey, iv: myIV),
            headerProtector: try suite.newHeaderProtector(trafficSecret: mySecret, version: self)
        )
    }

    private func computeInitialSecrets(connID: Quic.ConnectionID, v: Quic.Version) throws -> (clientSecret: SymmetricKey, serverSecret: SymmetricKey) {
        let suite = CipherSuite.AESGCM128_SHA256
        let initialSecret = SymmetricKey(data: Crypto.HKDF<SHA256>.extract(inputKeyMaterial: SymmetricKey(data: connID.withUnsafeBytes({ Array($0) })), salt: self.salt) )
        let clientSecret = try suite.expandLabel(pseudoRandomKey: initialSecret, label: "client in", outputByteCount: 32)
        let serverSecret = try suite.expandLabel(pseudoRandomKey: initialSecret, label: "server in", outputByteCount: 32)
        return (clientSecret, serverSecret)
    }

    private func computeInitialKeyAndIV(secret: SymmetricKey, v: Quic.Version) throws -> (key: SymmetricKey, iv: SymmetricKey) {
        try self.computeKeyAndIV(secret: secret, v: v, cipherSuite: CipherSuite.AESGCM128_SHA256)
    }

    private func computeKeyAndIV(secret: SymmetricKey, v: Quic.Version, cipherSuite suite: CipherSuite) throws -> (key: SymmetricKey, iv: SymmetricKey) {
        let key = try suite.expandLabel(pseudoRandomKey: secret, label: v.hkdfTrafficProtectionLabel, outputByteCount: suite.keyLength)
        let iv = try suite.expandLabel(pseudoRandomKey: secret, label: v.hkdfInitialVectorLabel, outputByteCount: suite.ivLength)
        return (key, iv)
    }
}
