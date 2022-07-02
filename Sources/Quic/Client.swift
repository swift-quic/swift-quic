//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

public protocol Client: Endpoint {
  static func bootstrap() async throws -> Self

  func connect() async throws -> Connection
}
