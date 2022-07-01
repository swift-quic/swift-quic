//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

protocol Packet {
  associatedtype HeaderType: Header
  var header: HeaderType { get }
  var payload: [UInt8] { get }
}
