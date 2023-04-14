
import Crypto
import Foundation

struct AESHeaderProtector: HeaderProtector {
  let sampleLength:Int = 16
  var cipher: any QMaskCipher
  var isLongHeader: Bool

  init(cipherSuite: CipherSuite, trafficSecret: SymmetricKey, isLongHeader: Bool, hkdfLabel: String) throws {
    let hpKey = try cipherSuite.expandLabel(pseudoRandomKey: trafficSecret, label: hkdfLabel, outputByteCount: cipherSuite.keyLength)
    self.cipher = AESECBMaskCipher(key: hpKey)
    self.isLongHeader = isLongHeader
  }
}
