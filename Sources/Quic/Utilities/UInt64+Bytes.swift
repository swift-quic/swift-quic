//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

extension UInt64 {
    func bytes(minBytes:Int = 0, bigEndian:Bool = true) -> [UInt8] {
        var bytes = Swift.withUnsafeBytes(of: bigEndian ? self.bigEndian : self.littleEndian, Array.init)
        while !bytes.isEmpty && bytes[0] == 0 && bytes.count > minBytes { bytes.removeFirst() }
        return bytes
    }
}

extension UInt32 {
    func bytes(minBytes:Int = 0, bigEndian:Bool = true) -> [UInt8] {
        var bytes = Swift.withUnsafeBytes(of: bigEndian ? self.bigEndian : self.littleEndian, Array.init)
        while !bytes.isEmpty && bytes[0] == 0 && bytes.count > minBytes { bytes.removeFirst() }
        return bytes
    }
}

extension UInt64 {
  init<T: Collection>(bytes: T) where T.Element == UInt8, T.Index == Int {
    precondition(bytes.count == 8, "UInt64 requires 8 bytes of info")
    
    // We break this into two parts to help the compiler type check it
    let startIndex = bytes.startIndex
    let val0 = (
      (UInt64(bytes[bytes.index(startIndex, offsetBy: 0)]) <<  0) |
      (UInt64(bytes[bytes.index(startIndex, offsetBy: 1)]) <<  8) |
      (UInt64(bytes[bytes.index(startIndex, offsetBy: 2)]) << 16) |
      (UInt64(bytes[bytes.index(startIndex, offsetBy: 3)]) << 24)
    )
    let val1 = (
      (UInt64(bytes[bytes.index(startIndex, offsetBy: 4)]) << 32) |
      (UInt64(bytes[bytes.index(startIndex, offsetBy: 5)]) << 40) |
      (UInt64(bytes[bytes.index(startIndex, offsetBy: 6)]) << 48) |
      (UInt64(bytes[bytes.index(startIndex, offsetBy: 7)]) << 56)
    )
  
    self = val0 | val1
  }
}

extension UInt32 {
  init<T: Collection>(bytes: T) where T.Element == UInt8, T.Index == Int {
    precondition(bytes.count == 4, "UInt32 requires 4 bytes of info")
    
    let startIndex = bytes.startIndex
    self = (
       (UInt32(bytes[bytes.index(startIndex, offsetBy: 0)]) <<  0) |
       (UInt32(bytes[bytes.index(startIndex, offsetBy: 1)]) <<  8) |
       (UInt32(bytes[bytes.index(startIndex, offsetBy: 2)]) << 16) |
       (UInt32(bytes[bytes.index(startIndex, offsetBy: 3)]) << 24)
    )
  }
}
