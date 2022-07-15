//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

enum StreamType: UInt8 {
  case clientBidi = 0b00
  case serverBidi = 0b01
  case clientUni = 0b10
  case serverUni = 0b11
}

extension StreamType: ByteFragment {
  static let mask: UInt8 = 0b11
}

extension StreamType {
  var origin: EndpointRole {
    EndpointRole(truncatingIfNeeded: rawValue)
  }

  var flowDirection: StreamFlowDirection {
    StreamFlowDirection(truncatingIfNeeded: rawValue)
  }
}
