//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

enum StreamFlowDirection: UInt8 {
  case biDirectional = 0
  case uniDirectional = 1
}

extension StreamFlowDirection {
  init(truncatingIfNeeded source: RawValue) {
    self.init(rawValue: source & 1)!
  }
}

extension StreamFlowDirection: Sendable, Hashable {}
