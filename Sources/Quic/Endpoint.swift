//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

/// Endpoint roles.
@frozen public enum Role {
  /// Client endpoint
  case client
  /// Server endpoint
  case server

  public func isClient() -> Bool {
    self == .client
  }

  public func isServer() -> Bool {
    self == .server
  }

  public func peerRole() -> Self {
    switch self {
    case .client: return .server
    case .server: return .client
    }
  }
}

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

extension Role: Sendable, Comparable, Hashable {}
extension Location: Sendable, Comparable, Hashable {}

public protocol Endpoint {
  var role: Role { get }
}
