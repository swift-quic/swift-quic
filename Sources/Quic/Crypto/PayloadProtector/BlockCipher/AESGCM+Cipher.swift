
import Crypto
import Foundation

public struct AESGCMBlockCipher:QBlockCipher {
    typealias cipher = Crypto.AES.GCM
    let key:SymmetricKey
    let iv:[UInt8]?
    
    init(key:SymmetricKey, iv:[UInt8]? = nil) {
        self.key = key
        self.iv = iv
    }
}

extension Crypto.AES.GCM:QCipher {
    static func encrypt<M, A>(message: M, using key: SymmetricKey, nonce:[UInt8]? = nil, authenticatingData: A) throws -> QSealedBox where M : DataProtocol, A : DataProtocol {
        if let nonce = nonce {
            let n = try AES.GCM.Nonce(data: nonce)
            return try seal(message, using: key, nonce: n, authenticating: authenticatingData)
        }
        return try seal(message, using: key, authenticating: authenticatingData)
    }
    
    static func decrypt<A>(_ sealedBox: QSealedBox, using key: SymmetricKey, authenticatingData authenticatedData: A) throws -> [UInt8] where A : DataProtocol {
      let sealed = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: sealedBox.qNonce), ciphertext: sealedBox.ciphertext, tag: sealedBox.tag)
      return try AES.GCM.open(sealed, using: key, authenticating: authenticatedData).withUnsafeBytes { Array($0) }
    }
}

extension Crypto.AES.GCM.SealedBox:QSealedBox {
    var qNonce: [UInt8] { self.nonce.withUnsafeBytes { Array($0) } }
}
