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

public enum EncodingType {
    case tlsRecord
    case cryptoFrame
    case headerless
}

public struct TLSRecordClientHello {
    public let header: [UInt8]
    public let handshakeType: [UInt8]
    public let tlsVersion: [UInt8]
    public let random: [UInt8]
    public let sessionID: [UInt8]?
    public let cipherSuites: [[UInt8]]
    public let compressionMethods: [[UInt8]]
    public var extensions: [Extension]

    public init(_ bytes: [UInt8], skipHeader: Bool = false) throws {
        var b = bytes

        if skipHeader {
            self.header = []
        } else {
            self.header = consumeBytes(5, from: &b)
            let recordLength = Int(Array(self.header[3...]).hexString, radix: 16)
            if recordLength != b.count {
                print("Warning: Record Length Byte Mismatch!!")
                print("Record Length: \(recordLength)")
                print("Byte Count: \(b.count)")
            }
        }
        self.handshakeType = consumeBytes(1, from: &b)
        let recordSize = try readInt(3, from: &b)
        guard recordSize <= b.count else {
            print("Warning: Record Size Mismatch!!")
            print("Record Size: \(recordSize)")
            print("Byte Count: \(b.count)")
            throw Errors.invalidRecordSize
        }
        self.tlsVersion = consumeBytes(2, from: &b)
        self.random = consumeBytes(32, from: &b)

        let sessionIDLength = try readInt(1, from: &b)
        if sessionIDLength > 0 {
            let sid = consumeBytes(sessionIDLength, from: &b)
            self.sessionID = sid
            print("Non nill session ID: \(sid.hexString)")
        } else {
            self.sessionID = nil
        }

        let cipherSuiteLength = try readInt(2, from: &b)
        print("Cipher Suite Length: \(cipherSuiteLength)")
        var supportedSuites: [[UInt8]] = []
        for _ in 0..<(cipherSuiteLength / 2) {
            supportedSuites.append(consumeBytes(2, from: &b))
        }
        self.cipherSuites = supportedSuites

        let compressionMethodsLength = try readInt(1, from: &b)
        print("Compression Methods Length: \(compressionMethodsLength)")
        var supportedMethods: [[UInt8]] = []
        for _ in 0..<compressionMethodsLength {
            supportedMethods.append(consumeBytes(1, from: &b))
        }
        self.compressionMethods = supportedMethods

        let extensionsLength = try readInt(2, from: &b)
        guard extensionsLength <= b.count else {
            print(extensionsLength)
            print(b.count)
            print(b.hexString)
            throw Errors.invalidExtensionSize
        }

        var exts: [Extension] = []
        while let ext = try? Extension(&b) {
            exts.append(ext)
        }
        self.extensions = exts
        //self.extensions = []
    }

    public func encode(as: EncodingType) -> [UInt8] {
        /// Build the extensions payload
        let extensionsValue = self.extensions.reduce(into: Array<UInt8>()) { partialResult, ext in
            partialResult.append(contentsOf: ext.encode())
        }
        let extensionLength = bytes(of: UInt16(extensionsValue.count), to: UInt8.self, droppingZeros: false)
        let extensionPayload = extensionLength + extensionsValue

        /// Build the compressions payload
        let compressionMethodsValue = self.compressionMethods.reduce(into: Array<UInt8>()) { partialResult, method in
            partialResult.append(contentsOf: method)
        }
        let compressionMethodsLength = bytes(of: UInt8(compressionMethodsValue.count), to: UInt8.self, droppingZeros: false)
        let compressionMethodsPayload = compressionMethodsLength + compressionMethodsValue

        /// Build the cipher suite payload
        let cipherSuitesValue = self.cipherSuites.reduce(into: Array<UInt8>()) { partialResult, suite in
            partialResult.append(contentsOf: suite)
        }
        let cipherSuitesLength = bytes(of: UInt16(cipherSuitesValue.count), to: UInt8.self, droppingZeros: false)
        let cipherSuitesPayload = cipherSuitesLength + cipherSuitesValue

        /// Build sessionID payload
        var sessionPayload: [UInt8] = [0x00] // null
        if let sessionID = self.sessionID {
            sessionPayload = bytes(of: UInt8(sessionID.count), to: UInt8.self, droppingZeros: false) + sessionID
        }

        var finalPayload = self.tlsVersion + self.random + sessionPayload + cipherSuitesPayload + compressionMethodsPayload + extensionPayload

        /// Prefix the payload with the length
        let finalPayloadLength = bytes(of: UInt32(finalPayload.count), to: UInt8.self, droppingZeros: false)
        finalPayload.insert(contentsOf: finalPayloadLength[1...], at: 0)

        switch `as` {
            case .tlsRecord:
                /// Prefix the payload with the type
                finalPayload.insert(contentsOf: self.handshakeType, at: 0)

                /// Prefix TLS Record Header
                let totalPayloadLength = bytes(of: UInt16(finalPayload.count), to: UInt8.self, droppingZeros: false)
                finalPayload.insert(contentsOf: [0x16, 0x03, 0x01] + totalPayloadLength, at: 0)

                return finalPayload
            case .cryptoFrame:
                /// Prefix the payload with the type
                finalPayload.insert(contentsOf: self.handshakeType, at: 0)

                /// Prefix TLS Record Header
                let totalPayloadLength = bytes(of: UInt8(finalPayload.count), to: UInt8.self, droppingZeros: false)
                finalPayload.insert(contentsOf: [0x06, 0x00, 0x40] + totalPayloadLength, at: 0)

                return finalPayload
            case .headerless:
                return finalPayload
        }
    }

    public mutating func removeExtension(_ type: [UInt8]) -> Extension? {
        if let match = self.extensions.firstIndex(where: { $0.type == type }) {
            return self.extensions.remove(at: match)
        }
        return nil
    }

    public mutating func addExtension(type: [UInt8], value: [UInt8]) {
        let ext = Extension(type: type, value: value)
        self.extensions.append(ext)
    }

    public enum Errors: Error {
        case invalidHexInt
        case invalidRecordSize
        case invalidExtensionSize
    }
}

public struct TLSRecordServerHello {
    public let header: [UInt8]
    public let handshakeType: [UInt8]
    public let tlsVersion: [UInt8]
    public let random: [UInt8]
    public let sessionID: [UInt8]?
    public let cipherSuite: [UInt8]
    public let compressionMethod: [UInt8]
    public var extensions: [Extension]

    public var padding: [UInt8] = []

    public init(_ bytes: [UInt8], skipHeader: Bool = false) throws {
        var b = bytes

        if skipHeader {
            self.header = []
        } else {
            self.header = consumeBytes(5, from: &b)
            let recordLength = Int(Array(self.header[3...]).hexString, radix: 16)
            if recordLength != b.count {
                print("Warning: Record Length Byte Mismatch!!")
                print("Record Length: \(recordLength!)")
                print("Byte Count: \(b.count)")
                self.padding = Array(b[recordLength!...])
                b = Array(b[0..<recordLength!])
            }
        }

        self.handshakeType = consumeBytes(1, from: &b)
        let recordSize = try readInt(3, from: &b)
        guard recordSize <= b.count else {
            print("Warning: Record Size Mismatch!!")
            print("Record Size: \(recordSize)")
            print("Byte Count: \(b.count)")
            throw Errors.invalidRecordSize
        }
        self.tlsVersion = consumeBytes(2, from: &b)
        self.random = consumeBytes(32, from: &b)

        let sessionIDLength = try readInt(1, from: &b)
        if sessionIDLength > 0 {
            let sid = consumeBytes(sessionIDLength, from: &b)
            self.sessionID = sid
            print("Non nill session ID: \(sid.hexString)")
        } else {
            self.sessionID = nil
        }

        self.cipherSuite = consumeBytes(2, from: &b)

        self.compressionMethod = consumeBytes(1, from: &b)

        let extensionsLength = try readInt(2, from: &b)
        guard extensionsLength <= b.count else {
            print(extensionsLength)
            print(b.count)
            print(b.hexString)
            throw Errors.invalidExtensionSize
        }

        var exts: [Extension] = []
        while let ext = try? Extension(&b) {
            exts.append(ext)
        }
        self.extensions = exts
        //self.extensions = []
    }

    public func encode(as: EncodingType) -> [UInt8] {
        /// Build the extensions payload
        let extensionsValue = self.extensions.reduce(into: Array<UInt8>()) { partialResult, ext in
            partialResult.append(contentsOf: ext.encode())
        }
        let extensionLength = bytes(of: UInt16(extensionsValue.count), to: UInt8.self, droppingZeros: false)
        let extensionPayload = extensionLength + extensionsValue

        /// Build sessionID payload
        var sessionPayload: [UInt8] = [0x00] // null
        if let sessionID = self.sessionID {
            sessionPayload = bytes(of: UInt8(sessionID.count), to: UInt8.self, droppingZeros: false) + sessionID
        }

        var finalPayload = self.tlsVersion + self.random + sessionPayload + self.cipherSuite + self.compressionMethod + extensionPayload

        /// Prefix the payload with the length
        let finalPayloadLength = bytes(of: UInt32(finalPayload.count), to: UInt8.self, droppingZeros: false)
        finalPayload.insert(contentsOf: finalPayloadLength[1...], at: 0)

        switch `as` {
            case .tlsRecord:
                /// Prefix the payload with the type
                finalPayload.insert(contentsOf: self.handshakeType, at: 0)

                /// Prefix TLS Record Header
                let totalPayloadLength = bytes(of: UInt16(finalPayload.count), to: UInt8.self, droppingZeros: false)
                finalPayload.insert(contentsOf: [0x16, 0x03, 0x01] + totalPayloadLength, at: 0)

                return finalPayload
            case .cryptoFrame:
                /// Prefix the payload with the type
                finalPayload.insert(contentsOf: self.handshakeType, at: 0)

                /// Prefix TLS Record Header
                let totalPayloadLength = bytes(of: UInt8(finalPayload.count), to: UInt8.self, droppingZeros: false)
                finalPayload.insert(contentsOf: try! Array(hexString: "0200000000060040") + totalPayloadLength, at: 0)

                return finalPayload
            case .headerless:
                return finalPayload
        }
    }

    public mutating func removeExtension(_ type: [UInt8]) -> Extension? {
        if let match = self.extensions.firstIndex(where: { $0.type == type }) {
            return self.extensions.remove(at: match)
        }
        return nil
    }

    public mutating func addExtension(type: [UInt8], value: [UInt8]) {
        let ext = Extension(type: type, value: value)
        self.extensions.append(ext)
    }

    public enum Errors: Error {
        case invalidHexInt
        case invalidRecordSize
        case invalidExtensionSize
    }
}

/// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
public struct Extension: CustomStringConvertible {
    public let type: [UInt8]
    public let value: [UInt8]

    public init(type: [UInt8], value: [UInt8]) {
        self.type = type
        self.value = value
    }

    public init(_ bytes: inout [UInt8]) throws {
        //var b = bytes
        guard bytes.count > 4 else { throw TLSRecordClientHello.Errors.invalidExtensionSize }
        //print("Parsing Extension From Bytes: \(bytes.hexString)")

        self.type = consumeBytes(2, from: &bytes)
        let length = try readInt(2, from: &bytes)
        self.value = consumeBytes(length, from: &bytes)
    }

    public func encode() -> [UInt8] {
        let length = bytes(of: UInt16(self.value.count), to: UInt8.self, droppingZeros: false)
        return self.type + length + self.value
    }

    public var typeToString: String {
        switch Int(self.type.hexString, radix: 16)! {
            case 0: return "server_name"
            case 1: return "max_fragment_length"
            case 2: return "client_certificate_url"
            case 3: return "trusted_ca_keys"
            case 4: return "truncated_hmac"
            case 5: return "status_request"
            case 6: return "user_mapping"
            case 7: return "client_authz"
            case 8: return "server_authz"
            case 9: return "cert_type"
            case 10: return "supported_groups"
            case 11: return "ec_point_formats"
            case 12: return "srp"
            case 13: return "signature_algorithms"
            case 14: return "use_srtp"
            case 15: return "heartbeat"
            case 16: return "application_layer_protocol_negotiation"
            case 17: return "status_request_v2"
            case 18: return "signed_certificate_timestamp"
            case 19: return "client_certificate_type"
            case 20: return "server_certificate_type"
            case 21: return "padding"
            case 22: return "encrypt_then_mac"
            case 23: return "extended_master_secret"
            case 24: return "token_binding"
            case 25: return "cached_info"
            case 26: return "tls_lts"
            case 27: return "compress_certificate"
            case 28: return "record_size_limit"
            case 29: return "pwd_protect"
            case 30: return "pwd_clear"
            case 31: return "password_salt"
            case 32: return "ticket_pinning"
            case 33: return "tls_cert_with_extern_psk"
            case 34: return "delegated_credentials"
            case 35: return "session_ticket"
            case 36: return "TLMSP"
            case 37: return "TLMSP_proxying"
            case 38: return "TLMSP_delegate"
            case 39: return "supported_ekt_ciphers"
            case 40: return "Reserved"
            case 41: return "pre_shared_key"
            case 42: return "early_data"
            case 43: return "supported_versions"
            case 44: return "cookie"
            case 45: return "psk_key_exchange_modes"
            case 46: return "Reserved"
            case 47: return "certificate_authorities"
            case 48: return "oid_filters"
            case 49: return "post_handshake_auth"
            case 50: return "signature_algorithms_cert"
            case 51: return "key_share"
            case 52: return "transparency_info"
            case 53: return "connection_id"
            case 54: return "connection_id"
            case 55: return "external_id_hash"
            case 56: return "external_session_id"
            case 57, 65445: return "quic_transport_parameters"
            case 58: return "ticket_request"
            case 59: return "dnssec_chain"
            default:
                return self.type.hexString
        }
    }

    public enum ExtensionType: Int {
        case server_name = 0
        case max_fragment_length
        case client_certificate_url
        case trusted_ca_keys
        case truncated_hmac
        case status_request
        case user_mapping
        case client_authz
        case server_authz
        case cert_type
        case supported_groups
        case ec_point_formats
        case srp
        case signature_algorithms
        case use_srtp
        case heartbeat
        case application_layer_protocol_negotiation
        case status_request_v2
        case signed_certificate_timestamp
        case client_certificate_type
        case server_certificate_type
        case padding
        case encrypt_then_mac
        case extended_master_secret
        case token_binding
        case cached_info
        case tls_lts
        case compress_certificate
        case record_size_limit
        case pwd_protect
        case pwd_clear
        case password_salt
        case ticket_pinning
        case tls_cert_with_extern_psk
        case delegated_credentials
        case session_ticket
        case TLMSP
        case TLMSP_proxying
        case TLMSP_delegate
        case supported_ekt_ciphers
        case Reserved
        case pre_shared_key
        case early_data
        case supported_versions
        case cookie
        case psk_key_exchange_modes
        case Reserved_2
        case certificate_authorities
        case oid_filters
        case post_handshake_auth
        case signature_algorithms_cert
        case key_share
        case transparency_info
        case connection_id
        case connection_id_2
        case external_id_hash
        case external_session_id
        case quic_transport_parameters
        case ticket_request
        case dnssec_chain
    }

    public var description: String {
        """
        \nExtension Type (\(self.typeToString) = \(self.type.hexString))
        Value: \(self.value.hexString)
        """
    }
    //\(self.values.map { $0.hexString }.joined(separator: "\n\t"))
}

private func readInt(_ bytes: Int, from: inout Array<UInt8>) throws -> Int {
    guard bytes < from.count else { throw TLSRecordClientHello.Errors.invalidHexInt }
    let consumed = Array(from[..<bytes])
    from = Array(from.dropFirst(bytes))
    guard let i = Int(consumed.hexString, radix: 16) else { throw TLSRecordClientHello.Errors.invalidHexInt }
    return i
}

private func consumeBytes(_ bytes: Int, from: inout Array<UInt8>) -> Array<UInt8> {
    guard from.count >= bytes else { return [] }
    let consumed = Array(from[..<bytes])
    from = Array(from.dropFirst(bytes))
    return consumed
}

private func bytes<U: FixedWidthInteger, V: FixedWidthInteger>(
    of value: U,
    to type: V.Type,
    droppingZeros: Bool
) -> [V] {

    let sizeInput = MemoryLayout<U>.size
    let sizeOutput = MemoryLayout<V>.size

    precondition(sizeInput >= sizeOutput, "The input memory size should be greater than the output memory size")

    var value = value
    let a = withUnsafePointer(to: &value, {
        $0.withMemoryRebound(
            to: V.self,
            capacity: sizeInput,
            {
                Array(UnsafeBufferPointer(start: $0, count: sizeInput / sizeOutput))
            }
        )
    })

    let lastNonZeroIndex =
        (droppingZeros ? a.lastIndex { $0 != 0 } : a.indices.last) ?? a.startIndex

    return Array(a[...lastNonZeroIndex].reversed())
}

public protocol TLSRecordExtensible {
    var extensions: [Extension] { get set }
    mutating func removeExtension(_ type: [UInt8]) -> Extension?
    mutating func addExtension(type: [UInt8], value: [UInt8])
}

public extension TLSRecordExtensible {
    mutating func removeExtension(_ type: [UInt8]) -> Extension? {
        if let match = self.extensions.firstIndex(where: { $0.type == type }) {
            return self.extensions.remove(at: match)
        }
        return nil
    }

    mutating func addExtension(type: [UInt8], value: [UInt8]) {
        let ext = Extension(type: type, value: value)
        self.extensions.append(ext)
    }
}

public extension Array where Element == Extension {
    func contains(type: Extension.ExtensionType) -> Bool {
        self.contains(where: { Int($0.type.hexString, radix: 16) == type.rawValue })
    }

    func first(whereType type: Extension.ExtensionType) -> Extension? {
        self.first(where: { Int($0.type.hexString, radix: 16) == type.rawValue })
    }
}

public struct ClientHello: TLSRecordExtensible {
    public let header: [UInt8]
    public let handshakeType: HandshakeType
    public let tlsVersion: [UInt8]
    public let random: [UInt8]
    public let sessionID: [UInt8]?
    public let cipherSuites: [[UInt8]]
    public let compressionMethods: [[UInt8]]
    public var extensions: [Extension]

    public init(fromTLSRecord bytes: [UInt8]) throws {
        var b = bytes

        let header = consumeBytes(5, from: &b)
        let recordLength = Int(Array(header[3...]).hexString, radix: 16)
        // TODO: Drop Padding Here
        if recordLength != b.count {
            print("Warning: Record Length Byte Mismatch!!")
            print("Record Length: \(recordLength!)")
            print("Byte Count: \(b.count)")
        }

        try self.init(header: header, payload: &b)
    }

    public init(fromCryptoFrame b: inout [UInt8]) throws {
        let header = consumeBytes(4, from: &b)
        let recordLength = Array(header[2...]).readQuicVarInt()! //- 1
        // TODO: Drop Padding Here
        if recordLength != b.count {
            print("Warning: Record Length Byte Mismatch!!")
            print("Record Length: \(recordLength)")
            print("Byte Count: \(b.count)")
        }

        try self.init(header: header, payload: &b)
    }

    public init(header: [UInt8], payload b: inout [UInt8]) throws {

        self.header = header

        guard let type = HandshakeType(rawValue: consumeBytes(1, from: &b).first!) else {
            throw Errors.invalidHandshakeType
        }
        self.handshakeType = type
        let recordSize = (try readInt(3, from: &b)) //- 1
        guard recordSize <= b.count else {
            print("Warning: Record Size Mismatch!!")
            print("Record Size: \(recordSize)")
            print("Byte Count: \(b.count)")
            throw Errors.invalidRecordSize
        }
        self.tlsVersion = consumeBytes(2, from: &b)
        self.random = consumeBytes(32, from: &b)

        let sessionIDLength = try readInt(1, from: &b)
        if sessionIDLength > 0 {
            let sid = consumeBytes(sessionIDLength, from: &b)
            self.sessionID = sid
            print("Non nill session ID: \(sid.hexString)")
        } else {
            self.sessionID = nil
        }

        let cipherSuiteLength = try readInt(2, from: &b)
        //print("Cipher Suite Length: \(cipherSuiteLength)")
        var supportedSuites: [[UInt8]] = []
        for _ in 0..<(cipherSuiteLength / 2) {
            supportedSuites.append(consumeBytes(2, from: &b))
        }
        self.cipherSuites = supportedSuites

        let compressionMethodsLength = try readInt(1, from: &b)
        //print("Compression Methods Length: \(compressionMethodsLength)")
        var supportedMethods: [[UInt8]] = []
        for _ in 0..<compressionMethodsLength {
            supportedMethods.append(consumeBytes(1, from: &b))
        }
        self.compressionMethods = supportedMethods

        let extensionsLength = try readInt(2, from: &b) //- 1
        guard extensionsLength <= b.count else {
            print(extensionsLength)
            print(b.count)
            print(b.hexString)
            throw Errors.invalidExtensionSize
        }

        var exts: [Extension] = []
        while let ext = try? Extension(&b) {
            exts.append(ext)
        }
        self.extensions = exts
    }

    public func encode(as: EncodingType) -> [UInt8] {
        /// Build the extensions payload
        let extensionsValue = self.extensions.reduce(into: Array<UInt8>()) { partialResult, ext in
            partialResult.append(contentsOf: ext.encode())
        }
        let extensionLength = bytes(of: UInt16(extensionsValue.count), to: UInt8.self, droppingZeros: false)
        let extensionPayload = extensionLength + extensionsValue

        /// Build the compressions payload
        let compressionMethodsValue = self.compressionMethods.reduce(into: Array<UInt8>()) { partialResult, method in
            partialResult.append(contentsOf: method)
        }
        let compressionMethodsLength = bytes(of: UInt8(compressionMethodsValue.count), to: UInt8.self, droppingZeros: false)
        let compressionMethodsPayload = compressionMethodsLength + compressionMethodsValue

        /// Build the cipher suite payload
        let cipherSuitesValue = self.cipherSuites.reduce(into: Array<UInt8>()) { partialResult, suite in
            partialResult.append(contentsOf: suite)
        }
        let cipherSuitesLength = bytes(of: UInt16(cipherSuitesValue.count), to: UInt8.self, droppingZeros: false)
        let cipherSuitesPayload = cipherSuitesLength + cipherSuitesValue

        /// Build sessionID payload
        var sessionPayload: [UInt8] = [0x00] // null
        if let sessionID = self.sessionID {
            sessionPayload = bytes(of: UInt8(sessionID.count), to: UInt8.self, droppingZeros: false) + sessionID
        }

        var finalPayload = self.tlsVersion + self.random + sessionPayload + cipherSuitesPayload + compressionMethodsPayload + extensionPayload

        /// Prefix the payload with the length
        let finalPayloadLength = bytes(of: UInt32(finalPayload.count), to: UInt8.self, droppingZeros: false)
        finalPayload.insert(contentsOf: finalPayloadLength[1...], at: 0)

        /// Prefix the payload with the type
        finalPayload.insert(self.handshakeType.rawValue, at: 0)

        switch `as` {
            case .tlsRecord:
                /// Prefix TLS Record Header
                let totalPayloadLength = bytes(of: UInt16(finalPayload.count), to: UInt8.self, droppingZeros: false)
                finalPayload.insert(contentsOf: [0x16, 0x03, 0x01] + totalPayloadLength, at: 0)

                return finalPayload
            case .cryptoFrame:
                /// Prefix Quic Crypto Frame Header
                //let totalPayloadLength = bytes(of: UInt16(finalPayload.count), to: UInt8.self, droppingZeros: false)
                let totalPayloadLength = writeQuicVarInt(UInt64(finalPayload.count))
                print("Final Payload Count: \(finalPayload.count)")
                print("Packet Payload Length: \(totalPayloadLength.hexString)")
                finalPayload.insert(contentsOf: [0x06, 0x00] + totalPayloadLength, at: 0)

                return finalPayload
            case .headerless:
                return finalPayload
        }
    }

    public enum Errors: Error {
        case invalidHexInt
        case invalidRecordSize
        case invalidExtensionSize
        case invalidHandshakeType
    }
}

public struct ServerHello: TLSRecordExtensible {
    public let header: [UInt8]
    public let handshakeType: HandshakeType
    public let tlsVersion: [UInt8]
    public let random: [UInt8]
    public let sessionID: [UInt8]?
    public let cipherSuite: [UInt8]
    public let compressionMethod: [UInt8]
    public var extensions: [Extension]

    public var padding: [UInt8] = []

    public init(fromTLSRecord bytes: [UInt8]) throws {
        var b = bytes

        let header = consumeBytes(5, from: &b)
        let recordLength = Int(Array(header[3...]).hexString, radix: 16)
        var padding: [UInt8] = []
        if recordLength != b.count {
            print("Warning: Record Length Byte Mismatch!!")
            print("Record Length: \(recordLength!)")
            print("Byte Count: \(b.count)")
            padding = Array(b[recordLength!...])
            /// Drop Padding....
            b = Array(b[0..<recordLength!])
        }

        try self.init(header: header, payload: &b, padding: padding)
    }

    public init(fromCryptoFrame bytes: [UInt8]) throws {
        var b = bytes

        let header = consumeBytes(4, from: &b)
        let recordLength = Int(Array(header[3...]).hexString, radix: 16)
        if recordLength != b.count {
            print("Warning: Record Length Byte Mismatch!!")
            print("Record Length: \(recordLength!)")
            print("Byte Count: \(b.count)")
            /// Drop Padding...
            b = Array(b[0..<(recordLength! - 1)])
        }

        try self.init(header: header, payload: &b)
    }

    public init(header: [UInt8], payload b: inout [UInt8], padding: [UInt8] = []) throws {
        self.header = header
        self.padding = padding

        guard let type = HandshakeType(rawValue: consumeBytes(1, from: &b).first!) else {
            throw Errors.invalidHandshakeType
        }
        self.handshakeType = type
        let recordSize = try readInt(3, from: &b)
        guard recordSize <= b.count else {
            print("Warning: Record Size Mismatch!!")
            print("Record Size: \(recordSize)")
            print("Byte Count: \(b.count)")
            throw Errors.invalidRecordSize
        }
        self.tlsVersion = consumeBytes(2, from: &b)
        self.random = consumeBytes(32, from: &b)

        let sessionIDLength = try readInt(1, from: &b)
        if sessionIDLength > 0 {
            let sid = consumeBytes(sessionIDLength, from: &b)
            self.sessionID = sid
            print("Non nill session ID: \(sid.hexString)")
        } else {
            self.sessionID = nil
        }

        self.cipherSuite = consumeBytes(2, from: &b)

        self.compressionMethod = consumeBytes(1, from: &b)

        let extensionsLength = try readInt(2, from: &b)
        guard extensionsLength <= b.count else {
            print(extensionsLength)
            print(b.count)
            print(b.hexString)
            throw Errors.invalidExtensionSize
        }

        var exts: [Extension] = []
        while let ext = try? Extension(&b) {
            exts.append(ext)
        }
        self.extensions = exts
        //self.extensions = []
    }

    public func encode(as: EncodingType) -> [UInt8] {
        /// Build the extensions payload
        let extensionsValue = self.extensions.reduce(into: Array<UInt8>()) { partialResult, ext in
            partialResult.append(contentsOf: ext.encode())
        }
        let extensionLength = bytes(of: UInt16(extensionsValue.count), to: UInt8.self, droppingZeros: false)
        let extensionPayload = extensionLength + extensionsValue

        /// Build sessionID payload
        var sessionPayload: [UInt8] = [0x00] // null
        if let sessionID = self.sessionID {
            sessionPayload = bytes(of: UInt8(sessionID.count), to: UInt8.self, droppingZeros: false) + sessionID
        }

        var finalPayload = self.tlsVersion + self.random + sessionPayload + self.cipherSuite + self.compressionMethod + extensionPayload

        /// Prefix the payload with the length
        let finalPayloadLength = bytes(of: UInt32(finalPayload.count), to: UInt8.self, droppingZeros: false)
        finalPayload.insert(contentsOf: finalPayloadLength[1...], at: 0)

        /// Prefix the payload with the type
        finalPayload.insert(self.handshakeType.rawValue, at: 0)

        switch `as` {
            case .tlsRecord:
                /// Prefix TLS Record Header
                let totalPayloadLength = bytes(of: UInt16(finalPayload.count), to: UInt8.self, droppingZeros: false)
                finalPayload.insert(contentsOf: [0x16, 0x03, 0x01] + totalPayloadLength, at: 0)

                return finalPayload
            case .cryptoFrame:
                /// Prefix TLS Record Header
                let totalPayloadLength = bytes(of: UInt8(finalPayload.count), to: UInt8.self, droppingZeros: false)
                finalPayload.insert(contentsOf: try! Array(hexString: "0200000000060040") + totalPayloadLength, at: 0)

                return finalPayload
            case .headerless:
                return finalPayload
        }
    }

    public enum Errors: Error {
        case invalidHexInt
        case invalidRecordSize
        case invalidExtensionSize
        case invalidHandshakeType
    }
}

// 14000020fad401b7c72d324c0466bf7d137f58924fc199ad00481adc0d2d7372f5aa9215
public struct ClientFinished {
    let headerTag: UInt8 //= 0x14
    let payload: [UInt8]

    public init(combined: [UInt8]) {
        self.headerTag = combined.first!
        // Read the length
        var lengthBytes = Array(combined[1..<4])
        let length = try! readInt(3, from: &lengthBytes)

        self.payload = Array(combined[4...])
        if self.payload.count != length {
            print("payload count \(self.payload.count) != length specified \(length)")
        }
    }

    public init(hash: [UInt8]) {
        self.headerTag = 0x14
        self.payload = hash
    }

    public func encode(as type: EncodingType) -> [UInt8] {
        var b = [headerTag]
        b += UInt64(self.payload.count).bytes(minBytes: 3)
        b += self.payload

        switch type {
            case .headerless:
                return b
            case .cryptoFrame:
                /// Crypto Frame Tag, Offset and Length
                let offset = [0x00]
                let length = writeQuicVarInt(UInt64(b.count))
                b.insert(contentsOf: [0x06, 0x00] + length, at: 0)
                return b
            case .tlsRecord:
                print("ERROR! We dont support encoding ClientFinished messages as \(type)")
                return []
        }
    }
}

public struct ServerFinished {
    let headerTag: UInt8 //= 0x14
    let payload: [UInt8]

    public init(combined: [UInt8]) {
        self.headerTag = combined.first!
        // Read the length
        var lengthBytes = Array(combined[1..<4])
        let length = try! readInt(3, from: &lengthBytes)

        self.payload = Array(combined[4...])
        if self.payload.count != length {
            print("payload count \(self.payload.count) != length specified \(length)")
        }
    }

    public init(hash: [UInt8]) {
        self.headerTag = 0x14
        self.payload = hash
    }

    public func encode(as type: EncodingType) -> [UInt8] {
        var b = [headerTag]
        b += UInt64(self.payload.count).bytes(minBytes: 3)
        b += self.payload

        switch type {
            case .headerless:
                return b
            case .cryptoFrame:
                /// Crypto Frame Tag, Offset and Length
                let offset = [0x00]
                let length = writeQuicVarInt(UInt64(b.count))
                b.insert(contentsOf: [0x06, 0x00] + length, at: 0)
                return b
            case .tlsRecord:
                print("ERROR! We dont support encoding ClientFinished messages as \(type)")
                return []
        }
    }
}

public enum HandshakeType: UInt8 {
    case hello_request_RESERVED = 0
    case client_hello = 1
    case server_hello = 2
    case hello_verify_request_RESERVED = 3
    case new_session_ticket = 4
    case end_of_early_data = 5
    case hello_retry_request_RESERVED = 6
    case encrypted_extensions = 8
    case certificate = 11
    case server_key_exchange_RESERVED = 12
    case certificate_request = 13
    case server_hello_done_RESERVED = 14
    case certificate_verify = 15
    case client_key_exchange_RESERVED = 16
    case finished = 20
    case certificate_url_RESERVED = 21
    case certificate_status_RESERVED = 22
    case supplemental_data_RESERVED = 23
    case key_update = 24
    case message_hash = 254
    //case 255
}
