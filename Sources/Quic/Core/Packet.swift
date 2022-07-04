//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

protocol Packet: Sendable, Hashable, Codable {
  associatedtype ConcreteHeader: Header
  var header: ConcreteHeader { get }
  var payload: [UInt8] { get }
}
