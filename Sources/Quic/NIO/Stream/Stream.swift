//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftQUIC open source project
//
// Copyright (c) 2023 the SwiftQUIC project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftQUIC project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Foundation
import NIOCore

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
    var origin: EndpointRole { self.type.origin }
    var flowDirection: StreamFlowDirection { self.type.flowDirection }
}
