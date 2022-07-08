//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

import Foundation

protocol Stream {
  var id: StreamID { get }
  var type: StreamType { get }
  var origin: EndpointRole { get }
  var flowDirection: StreamFlowDirection { get }

  func receive() async throws -> Data
  func send(_ data: Data) async throws
}

extension Stream {
  var type: StreamType { id.encodedType }
  var origin: EndpointRole { type.origin }
  var flowDirection: StreamFlowDirection { type.flowDirection }
}
