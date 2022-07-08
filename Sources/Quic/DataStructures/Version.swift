//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

struct Version: RawRepresentable {
  typealias RawValue = UInt32

  private let data: RawValue
  var rawValue: RawValue { data }
  init(rawValue: RawValue) {
    data = rawValue
  }
}

extension Version {
  static let negotiation: Version = 0
}

extension Version: Sendable, Hashable, Codable {}

extension Version: ExpressibleByIntegerLiteral {
  init(integerLiteral value: RawValue) {
    self.init(rawValue: value)
  }
}

fileprivate extension Version {
  func isNegotiation() -> Bool {
    data == 0
  }

  func isReserved() -> Bool {
    data & 0x0f0f0f0f == 0x0a0a0a0a
  }
}

func isNegotiation(version: Version) -> Bool {
  version.isNegotiation()
}

func isReserved(version: Version) -> Bool {
  version.isReserved()
}
