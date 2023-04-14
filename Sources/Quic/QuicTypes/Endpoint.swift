//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

/// Endpoint locations.
@frozen enum Location {
  /// Local endpoint
  case local
  /// Remote endpoint
  case remote

  public func isLocal() -> Bool {
    self == .local
  }

  public func isRemote() -> Bool {
    self == .remote
  }

  public func peerLocation() -> Self {
    switch self {
    case .local: return .remote
    case .remote: return .local
    }
  }
}

extension Location: Sendable, Comparable, Hashable {}

protocol Endpoint {
  var role: EndpointRole { get }
}
