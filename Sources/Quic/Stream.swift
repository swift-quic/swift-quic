//
//  Stream.swift
//
//
//  Created by Kenneth Laskoski on 04/06/22.
//

@available(macOS 10.15.0, *)
public struct Stream {
  public let connection: Connection
  private var peer: Peer! { connection.peer }

  public func receive() async throws -> String {
    try await Task.sleep(nanoseconds: 2 * 1_000_000_000)
    return await peer.send() ?? "###Empty###"
  }

  public func send(_ data: String) async throws {
    try await Task.sleep(nanoseconds: 2 * 1_000_000_000)
    await peer.receive(data)
  }
}
