//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

enum StreamFlowDirection: UInt8 {
  case biDirectional = 0b00
  case uniDirectional = 0b10
}

extension StreamFlowDirection {
  init(truncatingIfNeeded source: RawValue) {
    self.init(rawValue: source & 0b10)!
  }
}

extension StreamFlowDirection: Sendable, Hashable {}
