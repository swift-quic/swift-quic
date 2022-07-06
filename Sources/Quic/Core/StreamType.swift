//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

enum Direction: UInt8 {
  case biDirectional = 0
  case uniDirectional = 1
}

enum StreamType: UInt8 {
  case clientBidi = 0b00
  case serverBidi = 0b01
  case clientUni = 0b10
  case serverUni = 0b11
}

extension StreamType {
  var origin: Role {
    Role(rawValue: self.rawValue & 0b01)!
  }

  var direction: Direction {
    Direction(rawValue: self.rawValue & 0b10)!
  }
}
