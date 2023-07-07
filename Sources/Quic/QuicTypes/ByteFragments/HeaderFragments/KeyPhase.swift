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

enum KeyPhase: UInt8 {
    case not = 0b0000_0000
    case yes = 0b0000_0100
}

extension KeyPhase: ByteFragment {
    static let mask: UInt8 = 0b0000_0100

    mutating func toggle() {
        switch self {
            case .not:
                self = .yes
            case .yes:
                self = .not
        }
    }
}
