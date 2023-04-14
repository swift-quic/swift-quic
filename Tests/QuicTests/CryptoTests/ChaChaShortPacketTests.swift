

import Crypto
import XCTest
@testable import Quic

final class ChaChaShortPacketTests: XCTestCase {

  func testAppendix5ChaChaShortHeaderPacket_Manual() throws {
    let version = Version.version1
    let secret = try Array(hexString: "0x9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b")

    let keySet = try version.newAEAD(clientSecret: secret, serverSecret: secret, perspective: .client, suite: CipherSuite.ChaChaPoly_SHA256, epoch: .Application)

    // Key
    let expectedKey = try Array(hexString: "0xc6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8")
    XCTAssertEqual(keySet.sealer.encryptor.key.bytes, expectedKey)

    // IV
    let expectedIV = try Array(hexString: "0xe0459b3474bdd0e44a41c144")
    XCTAssertEqual(keySet.sealer.encryptor.iv, expectedIV)

    // HP
    let expectedHP = try Array(hexString: "0x25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4")
    XCTAssertEqual(keySet.sealer.headerProtector.cipher.key.bytes, expectedHP)

    struct MyShortHeader: ShortHeader, NumberedHeader {
      var destinationID: Quic.ConnectionID
      var packetNumberOffset: Int
      var firstByte: UInt8
      let packetNumber: [UInt8]

      var bytes: [UInt8] {
        [self.firstByte] + self.destinationID.rawValue + self.packetNumber
      }
    }

    struct MyShortPacket: Packet, NumberedPacket {
      let header: MyShortHeader
      let payload: [UInt8]
    }

    let largestAcked:UInt64 = 645_971_956  // Any lower and we'd have to send a 4 byte packet number
    let fullPacketNumber: UInt64 = 654_360_564
        
    let encodedPN = encodePacketNumber(fullPacketNumber: fullPacketNumber, largestAcked: largestAcked)
    XCTAssertEqual(UInt64(bytes: ([0x00, 0x00, 0x00, 0x00, 0x00] + encodedPN).reversed()), UInt64(49_140))
    
    let varInt = writeQuicVarInt(fullPacketNumber)
    let recovered = varInt.readQuicVarInt()
    XCTAssertEqual(recovered, fullPacketNumber)

    let unprotectedHeader = MyShortHeader(destinationID: ConnectionID(), packetNumberOffset: 1, firstByte: 0x42, packetNumber: encodedPN)
    XCTAssertEqual(unprotectedHeader.bytes, try Array(hexString: "4200bff4"))
    
    /// - Note: We need to pass the full original packet number into the encryptPayload function, not the encoded packet number!
    let ciphertext = try keySet.encryptPayload(message: [0x01], packetNumber: fullPacketNumber.bytes(), authenticatingData: unprotectedHeader.bytes)
    let encryptedPayload = Array(ciphertext.ciphertext + ciphertext.tag)
    XCTAssertEqual(encryptedPayload.hexString, "655e5cd55c41f69080575d7999c25a5bfb")

    var protectedHeader = unprotectedHeader.bytes
    print("UnprotectedHeader[\(protectedHeader.count)]: \(protectedHeader)")
    try keySet.applyHeaderProtection(sample: encryptedPayload[1..<17], headerBytes: &protectedHeader, packetNumberOffset: unprotectedHeader.packetNumberOffset)

    XCTAssertEqual(protectedHeader.hexString, "4cfe4189")

    let finalPacket = protectedHeader + encryptedPayload
    XCTAssertEqual(finalPacket.hexString, "4cfe4189655e5cd55c41f69080575d7999c25a5bfb")
  }
}
