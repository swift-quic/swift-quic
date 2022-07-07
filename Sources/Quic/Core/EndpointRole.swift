//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

enum EndpointRole: UInt8 {
  case client = 0
  case server = 1
}

extension EndpointRole {
  init(truncating rawValue: RawValue) {
    self.init(rawValue: rawValue & 1)!
  }
}

extension EndpointRole: Sendable, Hashable {}
