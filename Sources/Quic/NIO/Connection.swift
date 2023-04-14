//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

protocol Connection {
  func accept() async throws -> Stream
}
