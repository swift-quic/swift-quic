//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

enum Role: UInt8 {
  case client = 0
  case server = 1
}

extension Role: Sendable, Hashable {}
