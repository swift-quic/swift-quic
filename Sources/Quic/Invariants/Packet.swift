//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

protocol Packet {
  var header: Header { get }
  var payload: [UInt8] { get }
}
