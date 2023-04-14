
import _CryptoExtras
import Crypto
import Foundation

struct ChaCha20CTRMaskCipher: QMaskCipher {
  typealias cipher = Insecure.ChaCha20CTR
  let key: SymmetricKey

  init(key: SymmetricKey) {
    self.key = key
  }
}

extension Insecure.ChaCha20CTR: QMasker {
  static func generateMask<SAMPLE>(sample: SAMPLE, using key: SymmetricKey) throws -> [UInt8] where SAMPLE : ContiguousBytes {
      return try sample.withUnsafeBytes { samplePtr in
          guard samplePtr.count == 16 else { throw Errors.Crypto(0) }
          let counter = samplePtr.prefix(4)
          let iv = samplePtr.suffix(12)
          
          return try Array(Insecure.ChaCha20CTR.encrypt(Array<UInt8>(repeating: 0, count: 5), using: key, counter: .init(data: counter), nonce: .init(data: iv)))
      }
  }
    
  static func encrypt<M>(message: M, using key: SymmetricKey, nonce: [UInt8]?) throws -> [UInt8] where M: DataProtocol {
    guard let nonce = nonce, nonce.count == 16, message.count == 5 else { throw Errors.Crypto(0) }

    let counter = nonce.prefix(4)
    let iv = nonce.suffix(12)

    return try Array(Insecure.ChaCha20CTR.encrypt(message, using: key, counter: .init(data: counter), nonce: .init(data: iv)))
  }
}
