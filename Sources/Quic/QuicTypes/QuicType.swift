//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

import Foundation

protocol QuicType: Sendable, Hashable, ContiguousBytes {
  init<S: Sequence>(with bytes: S) where S.Element == UInt8
  var bytes: [UInt8] { get }
}

extension QuicType {
  func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
    try bytes.withUnsafeBytes(body)
  }
}
