//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

enum StreamType: UInt8 {
  case clientBidi = 0b00
  case serverBidi = 0b01
  case clientUni = 0b10
  case serverUni = 0b11
}

extension StreamType {
  var origin: EndpointRole {
    EndpointRole(rawValue: self.rawValue & 0b01)!
  }

  var flowDirection: StreamFlowDirection {
    StreamFlowDirection(rawValue: (self.rawValue & 0b10))!
  }
}

extension StreamType {
  init(truncatingIfNeeded source: RawValue) {
    self.init(rawValue: source & 0b11)!
  }
}

extension StreamType: Sendable, Hashable {}
