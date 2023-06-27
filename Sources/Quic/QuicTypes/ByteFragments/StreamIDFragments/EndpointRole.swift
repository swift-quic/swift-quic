//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

enum EndpointRole: UInt8 {
  case client = 0
  case server = 1
}

extension EndpointRole: ByteFragment {
  static let mask: UInt8 = 1
}

extension EndpointRole {
    var opposite:EndpointRole {
        switch self {
        case .client: return .server
        case .server: return .client
        }
    }
}
