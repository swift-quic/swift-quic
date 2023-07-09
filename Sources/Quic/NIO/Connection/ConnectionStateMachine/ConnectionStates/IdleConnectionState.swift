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

extension QUICConnectionStateMachine {
    struct IdleState {
        let role: EndpointRole
        let epoch: Epoch = .Initial

        init(role: EndpointRole) {
            self.role = role
        }
    }
}
