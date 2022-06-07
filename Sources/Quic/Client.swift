//
//  Client.swift
//
//
//  Created by Kenneth Laskoski on 06/06/22.
//

import Socket

public struct Client {
  private let socket: Socket
  public init() async throws {
    socket = try await Socket(
        IPv4Protocol.tcp
    )
  }

  public static func bootstrap() async throws -> Client {
    try await Client()
  }

  public func connect() async throws -> Connection {
    let address = IPv4SocketAddress(address: IPv4Address(rawValue: "127.0.0.1")!, port: 8888)
    do {
      try await socket.fileDescriptor.connect(to: address, sleep: 1_000_000_000)
    } catch Errno.socketIsConnected {}
    return Connection(socket: socket)
  }
}
