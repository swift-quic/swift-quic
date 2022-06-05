//
//  Connection.swift
//  
//
//  Created by Kenneth Laskoski on 04/06/22.
//

import Socket

@available(macOS 10.15.0, *)
public struct Connection {
  private let socket: Socket
  public init(socket: Socket) {
    self.socket = socket
  }

  public func accept() async throws -> Stream {
    return Stream(connection: self, socket: socket)
  }
}
