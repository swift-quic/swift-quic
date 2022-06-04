//
//  Server.swift
//
//
//  Created by Kenneth Laskoski on 04/06/22.
//

@available(macOS 10.15.0, *)
public struct Server {
  public static func bootstrap() async throws -> Server {
    try await Task.sleep(nanoseconds: 2 * 1_000_000_000)
    return Server()
  }

  public func accept() async throws -> Connection {
    try await Task.sleep(nanoseconds: 2 * 1_000_000_000)
    return Connection()
  }
}
