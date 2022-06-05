//
//  Stream.swift
//
//
//  Created by Kenneth Laskoski on 04/06/22.
//

import Socket
import Foundation

@available(macOS 10.15.0, *)
public struct Stream {
  private let connection: Connection
  private let socket: Socket
  public init(connection: Connection, socket: Socket) {
    self.connection = connection
    self.socket = socket
  }

  public func receive() async throws -> Data {
    try await socket.read(1024)
  }

  public func send(_ data: Data) async throws {
    try await socket.write(data)
  }
}
