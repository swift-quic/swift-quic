//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

import Foundation

protocol Stream {
  var type: StreamType { get }
  var origin: EndpointRole { get }
  var direction: Direction { get }

  func receive() async throws -> Data
  func send(_ data: Data) async throws
}

extension Stream {
  var origin: EndpointRole { type.origin }
  var direction: Direction { type.direction }
}
