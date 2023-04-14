//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

struct HandshakeHeader: TypedHeader, NumberedHeader {
  let type:LongPacketType = .handshake
  var version: Version

  var destinationIDLength: UInt8 { UInt8(truncatingIfNeeded: destinationID.length) }
  let destinationID: ConnectionID

  var sourceIDLength: UInt8 { UInt8(truncatingIfNeeded: sourceID.length) }
  let sourceID: ConnectionID
  
  var packetLength: UInt64
  var packetNumber: [UInt8]

  init(version: Version, destinationID: ConnectionID, sourceID: ConnectionID, packetLength:UInt64 = 0, packetNumber: [UInt8] = []) {
    self.version = version
    self.destinationID = destinationID
    self.sourceID = sourceID
    self.packetLength = packetLength
    self.packetNumber = packetNumber
  }
  
  var bytes:[UInt8] {
    var bytes = [firstByte]
    bytes += version.withUnsafeBytes { Array($0) }
    bytes += destinationID.lengthPrefixedBytes
    bytes += sourceID.lengthPrefixedBytes
    bytes += writeQuicVarInt(packetLength)
    bytes += packetNumber
    return bytes
  }
  
  var packetNumberOffset: Int {
    self.bytes.count - packetNumber.count
  }
  
  mutating func setPacketNumber(_ pn:[UInt8]) {
    self.packetNumber = pn
  }
  
  mutating func setPacketLength(_ pl:UInt64) {
    self.packetLength = pl
  }
}

struct HandshakePacket: Packet, NumberedPacket {
  let header: HandshakeHeader
  var payload:[UInt8]
    
  init(header:HandshakeHeader, payload:[UInt8]) {
    self.header = header
    self.payload = payload
  }
    
  init(version:Version, destinationID: ConnectionID, sourceID: ConnectionID, packetNumber:[UInt8]) {
    self.header = HandshakeHeader(
      version: version,
      destinationID: destinationID,
      sourceID: sourceID,
      packetNumber: packetNumber
    )
    self.payload = []
  }
}
