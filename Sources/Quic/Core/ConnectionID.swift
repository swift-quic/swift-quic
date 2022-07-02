//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

fileprivate let maxCount = Int(UInt8.max)

struct ConnectionID: RawRepresentable {
  typealias RawValue = [UInt8]
  let data: RawValue

  var rawValue: RawValue { data }
  init(rawValue: RawValue) {
    let slice = rawValue[0..<maxCount]
    data = RawValue(slice)
  }

  var length: UInt8 { UInt8(rawValue.count) }
}

extension ConnectionID: Sendable, Hashable, Codable {}
