//
//  Version+Salt.swift
//
//
//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

// Key Generation Params
extension Version {
  /// Initial Salt v2
  /// https://datatracker.ietf.org/doc/draft-ietf-quic-v2/
  static internal let QUIC_SALT_V2 = Array<UInt8>(arrayLiteral: 0xa7, 0x07, 0xc2, 0x03, 0xa5, 0x9b, 0x47, 0x18, 0x4a, 0x1d, 0x62, 0xca, 0x57, 0x04, 0x06, 0xea, 0x7a, 0xe3, 0xe5, 0xd3)
  
  /// Initial Salt v1
  /// https://datatracker.ietf.org/doc/html/rfc9001
  static internal let QUIC_SALT_V1 = Array<UInt8>(arrayLiteral: 0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a)
  
  /// Initial Salt Draft 29
  /// https://datatracker.ietf.org/doc/html/draft-ietf-quic-tls-29
  static internal let QUIC_SALT_DRAFT_29 = Array<UInt8>(arrayLiteral: 0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99)

  /// Version specific Salt used for Initial KeySet Generation
  public var salt: [UInt8] {
    switch self {
      case .version2:
        return Version.QUIC_SALT_V2
      case .version1:
        return Version.QUIC_SALT_V1
      case .versionDraft29:
        return Version.QUIC_SALT_DRAFT_29
      default:
        preconditionFailure("Unsupported Quic Version \(self)")
    }
  }

  /// HKDF label "client in"
  /// - Note: This is just the UTF8 Bytes of the string "client in"
  /// - Note: Not currently version dependent but defined here in case this changes in the future
  static public var clientInitial: [UInt8] = [0x00, 0x20, 0x0f, 0x74, 0x6c, 0x73, 0x31, 0x33, 0x20, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x20, 0x69, 0x6e, 0x00]

  /// HKDF label "server in"
  /// - Note: This is just the UTF8 Bytes of the string "server in"
  /// - Note: Not currently version dependent but defined here in case this changes in the future
  static public var serverInitial: [UInt8] = [0x00, 0x20, 0x0f, 0x74, 0x6c, 0x73, 0x31, 0x33, 0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x69, 0x6e, 0x00]

  /// Packet Protection Sample Length
  /// - Note: Not currently version dependent but defined here in case this changes in the future
  static public var sampleLength: Int = 16

  static private let HKDF_LABEL_HP_V1 = "quic hp"
  static private let HKDF_LABEL_HP_V2 = "quicv2 hp"
  
  /// Header Protection Key Generation Label
  /// - Note: To be used along side the `HKDF` to generate the `Key` used in conjuction with the `Sample` to generate the header protection `Mask`.
  public var hkdfHeaderProtectionLabel: String {
    switch self {
      case .version2:
        return Version.HKDF_LABEL_HP_V2
      default:
        return Version.HKDF_LABEL_HP_V1
    }
  }

  static private let HKDF_LABEL_KEY_V1 = "quic key"
  static private let HKDF_LABEL_KEY_V2 = "quicv2 key"
  
  /// Traffic Protection Key Generation Label
  /// - Note: To be used along side the `HKDF` to generate the `Key` used to initialize the `AES.Cipher` for packet protection.
  public var hkdfTrafficProtectionLabel: String {
    switch self {
      case .version2:
        return Version.HKDF_LABEL_KEY_V2
      default:
        return Version.HKDF_LABEL_KEY_V1
    }
  }

  static private let HKDF_LABEL_IV_V1 = "quic iv"
  static private let HKDF_LABEL_IV_V2 = "quicv2 iv"
  
  /// Initial Vector Key Generation Label
  /// - Note: To be used along side the `HKDF` to generate the `Initial Vector` used in conjuction with the `PacketNumber` to generate the `Nonce` used to initialize the `AES.Cipher` for packet protection.
  public var hkdfInitialVectorLabel: String {
    switch self {
      case .version2:
        return Version.HKDF_LABEL_IV_V2
      default:
        return Version.HKDF_LABEL_IV_V1
    }
  }
}
