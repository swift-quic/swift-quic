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

enum EndpointRole: UInt8 {
    case client = 0
    case server = 1
}

extension EndpointRole: ByteFragment {
    static let mask: UInt8 = 1
}

extension EndpointRole {
    var opposite: EndpointRole {
        switch self {
            case .client: return .server
            case .server: return .client
        }
    }
}

extension EndpointRole {
    var opposite:EndpointRole {
        switch self {
        case .client: return .server
        case .server: return .client
        }
    }
}
