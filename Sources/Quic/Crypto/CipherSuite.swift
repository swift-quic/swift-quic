

import Crypto

enum CipherSuite:CaseIterable {
    case AESGCM128_SHA256
    case AESGCM256_SHA384
    case ChaChaPoly_SHA256
    
    /// Instantiates a Cipher Suite based on the TLS 2 byte Cipher Suite code
    ///
    /// https://www.rfc-editor.org/rfc/rfc8446.html#appendix-B.4
    /// ```
    /// +------------------------------+-------------+
    /// | Description                  | Value       |
    /// +------------------------------+-------------+
    /// | TLS_AES_128_GCM_SHA256       | {0x13,0x01} |
    /// |                              |             |
    /// | TLS_AES_256_GCM_SHA384       | {0x13,0x02} |
    /// |                              |             |
    /// | TLS_CHACHA20_POLY1305_SHA256 | {0x13,0x03} |
    /// |                              |             |
    /// | TLS_AES_128_CCM_SHA256       | {0x13,0x04} |
    /// |                              |             |
    /// | TLS_AES_128_CCM_8_SHA256     | {0x13,0x05} |
    /// +------------------------------+-------------+
    /// ```
    init(_ bytes:[UInt8]) throws {
        switch bytes {
        case [0x13, 0x01]:
            self = .AESGCM128_SHA256
        case [0x13, 0x02]:
            self = .AESGCM256_SHA384
        case [0x13, 0x03]:
            self = .ChaChaPoly_SHA256
        case [0x13, 0x04]:
            throw Errors.UnsupportedCipherSuite(name: "TLS_AES_128_CCM_SHA256")
        case [0x13, 0x05]:
            throw Errors.UnsupportedCipherSuite(name: "TLS_AES_128_CCM_8_SHA256")
        default:
            throw Errors.UnknownCipherSuite(code: bytes)
        }
    }
    
    func newHeaderProtector(trafficSecret:SymmetricKey, version:Quic.Version) throws -> HeaderProtector {
        switch self {
        case .AESGCM128_SHA256, .AESGCM256_SHA384:
            return try AESHeaderProtector(cipherSuite: self, trafficSecret: trafficSecret, isLongHeader: true, hkdfLabel: version.hkdfHeaderProtectionLabel)
        case .ChaChaPoly_SHA256:
            return try ChaChaHeaderProtector(cipherSuite: self, trafficSecret: trafficSecret, isLongHeader: false, hkdfLabel: version.hkdfHeaderProtectionLabel)
        }
    }
  
    func newBlockCipher(key:SymmetricKey, iv:SymmetricKey) throws -> any QBlockCipher {
      switch self {
        case .AESGCM128_SHA256, .AESGCM256_SHA384:
           return AESGCMBlockCipher(key: key, iv: iv.withUnsafeBytes({ Array($0) }))
        case .ChaChaPoly_SHA256:
          return ChaChaPolyCipher(key: key, iv: iv.withUnsafeBytes({ Array($0) }))
      }
    }
    
    func expandLabel(pseudoRandomKey:SymmetricKey, label:String, outputByteCount:Int? = nil) throws -> SymmetricKey {
        switch self {
        case .AESGCM128_SHA256, .ChaChaPoly_SHA256:
            return try Crypto.HKDF<SHA256>.expandLabel(pseudoRandomKey: pseudoRandomKey, label: label, outputByteCount: outputByteCount ?? self.keyLength)
        case .AESGCM256_SHA384:
            return try Crypto.HKDF<SHA384>.expandLabel(pseudoRandomKey: pseudoRandomKey, label: label, outputByteCount: outputByteCount ?? self.keyLength)
        }
    }
    
//    func generateKeySet(pseudoRandomKey:SymmetricKey, version:Quic.Version) throws -> KeySet {
//        return try KeySet(
//            key: self.expandLabel(pseudoRandomKey: pseudoRandomKey, label: version.hkdfTrafficProtectionLabel, outputByteCount: self.keyLength),
//            iv: self.expandLabel(pseudoRandomKey: pseudoRandomKey, label: version.hkdfInitialVectorLabel, outputByteCount: self.ivLength),
//            hp: self.expandLabel(pseudoRandomKey: pseudoRandomKey, label: version.hkdfHeaderProtectionLabel, outputByteCount: self.keyLength)
//        )
//    }
    
    var keyLength:Int {
        switch self {
        case .AESGCM128_SHA256:
            return 16
        case .AESGCM256_SHA384, .ChaChaPoly_SHA256:
            return 32
        }
    }
    
    /// IV / Nonce Length
    var ivLength:Int {
        return 12
    }
    
    /// AEAD Tag Length
    var tagLength:Int {
        return 16
    }
}
