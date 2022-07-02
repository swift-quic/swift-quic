//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

import Foundation

public protocol Stream {
  func receive() async throws -> Data
  func send(_ data: Data) async throws
}
