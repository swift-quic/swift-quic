//
//  Server.swift
//
//
//  Created by Kenneth Laskoski on 04/06/22.
//

import Socket

@available(macOS 10.15.0, *)
public struct Server {
  private let socket: Socket
  public init() async throws {
    let address = IPv4SocketAddress(address: .any, port: 8888)
    socket = try await Socket(
        IPv4Protocol.tcp,
        bind: address
    )
    try socket.fileDescriptor.listen(backlog: 10)
  }

  public static func bootstrap() async throws -> Server {
    try await Server()
  }

  public func accept() async throws -> Connection {
    let newConnection = await Socket(
        fileDescriptor: try await socket.fileDescriptor.accept()
    )
    return Connection(socket: newConnection)
  }
}
