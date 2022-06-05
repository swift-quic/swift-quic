//
//  Connection.swift
//  
//
//  Created by Kenneth Laskoski on 04/06/22.
//

import Foundation

@available(macOS 10.15.0, *)
public struct Connection {
  var peer: Peer!
  init() {
    peer = Peer(connection: self)
  }

  private let address = UUID()
  public var localAddress: UUID { address }
  public var remoteAddress: UUID? { get async { await peer?.localAddress } }

  public func accept() async throws -> Stream {
    try await Task.sleep(nanoseconds: 2 * 1_000_000_000)
    return Stream(connection: self)
  }
}

@available(macOS 10.15.0, *)
actor Peer {
  private let peer: Connection
  init(connection: Connection) {
    peer = connection
  }

  private var received = [String]()

  private let address = UUID()
  public var localAddress: UUID { address }
  public var remoteAddress: UUID? { peer.localAddress }

  func send() -> String? {
    return received.last
  }

  func receive(_ new: String) {
    received.append(new)
  }
}
