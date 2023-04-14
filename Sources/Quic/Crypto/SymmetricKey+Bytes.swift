

import Crypto

extension SymmetricKey {
    var bytes:[UInt8] {
        self.withUnsafeBytes { Array($0) }
    }
}
