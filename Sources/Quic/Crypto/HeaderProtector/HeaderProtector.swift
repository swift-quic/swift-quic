
import Crypto
import Foundation

protocol HeaderProtector {
  var sampleLength: Int { get }
  var cipher: any QMaskCipher { get }
  var isLongHeader: Bool { get }
}

extension HeaderProtector {
  /// Generates and applies the `Header Protection Mask` to the header.
  /// - Parameters:
  ///   - sample: The sample extracted from the encrypted payload, this sample is used to generate the Mask.
  ///   - hdrBytes: The entirety of the header (if protected this needs to include all potential packet number bytes)
  ///   - packetNumberOffset: The Integer offset of the PacketNumber in the Header
  /// - Note: This operation is bi-directional, if the header is currently protected, invoking this function will result in an unprotected header. If the header is currently unprotected, invoking this function will result in a protected header.
  func applyMask<SAMPLE, BYTES>(sample: SAMPLE, hdrBytes: inout BYTES, packetNumberOffset: Int) throws where SAMPLE: ContiguousBytes, BYTES: ContiguousBytes {
    let sample = sample.withUnsafeBytes { Array($0) }
    guard sample.count == sampleLength else { preconditionFailure("Invalid Sample Size \(sample.count) != \(sampleLength)") }

    // Generate the Mask and
    let mask = try self.cipher.generateMask(sample: sample)
    
    var header = hdrBytes.withUnsafeBytes { Array($0) }

    if self.isLongHeader {
      header[0] ^= mask[0] & 0x0f
    } else {
      header[0] ^= mask[0] & 0x1f
    }
    // Apply the mask to the packet number
    header.xorSubrange(from: packetNumberOffset, to: header.count, with: Array(mask[1...]))

    hdrBytes = header as! BYTES
  }
}

protocol QMasker {
  static func generateMask<SAMPLE>(sample: SAMPLE, using: SymmetricKey) throws -> [UInt8] where SAMPLE: ContiguousBytes
}

protocol QMaskCipher {
  associatedtype cipher: QMasker
  var key: SymmetricKey { get }
}

extension QMaskCipher {
  func generateMask<SAMPLE>(sample: SAMPLE) throws -> [UInt8] where SAMPLE: ContiguousBytes {
    try cipher.generateMask(sample: sample, using: key)
  }
}
