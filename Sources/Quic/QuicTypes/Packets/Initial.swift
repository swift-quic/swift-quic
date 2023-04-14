//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

struct InitialHeader: TypedHeader, NumberedHeader {
  let type: LongPacketType = .initial
  var version: Version

  var destinationIDLength: UInt8 { UInt8(truncatingIfNeeded: destinationID.length) }
  let destinationID: ConnectionID

  var sourceIDLength: UInt8 { UInt8(truncatingIfNeeded: sourceID.length) }
  let sourceID: ConnectionID
  
  var token: [UInt8]
  
  var packetLength: UInt64
  var packetNumber: [UInt8]
    
  init(version: Version, destinationID: ConnectionID, sourceID: ConnectionID, token: [UInt8] = [], packetLength:UInt64 = 0, packetNumber: [UInt8] = []) {
    self.version = version
    self.destinationID = destinationID
    self.sourceID = sourceID
    self.token = token
    self.packetNumber = packetNumber
    self.packetLength = packetLength
  }
  
  var bytes:[UInt8] {
    var bytes = [firstByte]
    bytes += version.withUnsafeBytes { Array($0) }
    bytes += destinationID.lengthPrefixedBytes
    bytes += sourceID.lengthPrefixedBytes
    bytes += writeQuicVarInt(UInt64(token.count))
    bytes += token
    bytes += writeQuicVarInt(packetLength)
    bytes += packetNumber
    return bytes
  }
  
  // Magic 5 is first byte + version
  var packetNumberOffset: Int {
    self.bytes.count - packetNumber.count
    //5 + destinationID.length + sourceID.length + token.count + writeQuicVarInt(packetLength).count
  }
  
  mutating func setPacketNumber(_ pn:[UInt8]) {
    self.packetNumber = pn
  }
  
  mutating func setPacketLength(_ pl:UInt64) {
    self.packetLength = pl
  }
}

struct InitialPacket: Packet, NumberedPacket {
  var header: InitialHeader
  var payload:[UInt8] {
    didSet {
      let tagLength = 16
      self.header.setPacketLength(UInt64(payload.count + tagLength + header.packetNumber.count))
    }
  }
  var packetNumber: [UInt8] { header.packetNumber }
    
  init(header:InitialHeader, payload:[UInt8]) {
    self.header = header
    self.payload = payload
  }
    
  init(version: Version, destinationID: ConnectionID, sourceID: ConnectionID, token:[UInt8] = [], packetLength:UInt64 = 0, packetNumber:[UInt8] = []) {
    self.header = InitialHeader(
      version: version,
      destinationID: destinationID,
      sourceID: sourceID,
      token: token,
      packetLength: packetLength,
      packetNumber: packetNumber
    )
    self.payload = []
  }
}

