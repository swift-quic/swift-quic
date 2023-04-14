//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

import Foundation

extension Array where Element == UInt8 {
  mutating func xor(with other: [UInt8]) {
    guard self.count <= other.count else { fatalError("Array must be of greater than or equal length to that of the XOR stream.") }
    for i in 0..<self.count {
      self[i] ^= other[i]
    }
  }

  mutating func xorSubrange(from start: Int, to end: Int, with other: [UInt8]) {
    guard start >= 0, end <= count, start <= end, end - start <= other.count else { fatalError("Invalid subrange or array length.") }
    for i in start..<end {
      self[i] ^= other[i - start]
    }
  }
}
