//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

import Foundation

protocol QuicType: Sendable, Hashable, ContiguousBytes {
  init(with bytes: UnsafeBufferPointer<UInt8>)
}
