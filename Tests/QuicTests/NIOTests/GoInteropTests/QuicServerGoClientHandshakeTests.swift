//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftQUIC open source project
//
// Copyright (c) 2023 the SwiftQUIC project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftQUIC project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIO
import NIOSSL
import XCTest
@testable import Quic

/// Swift QUIC Server <-> Go Client Handshake Test
///
/// This test is meant to be run in conjunction with a Go QUIC Client that extablishes a connection, opens a stream, and sends a string to be echo'd
///
/// Usage:
/// 1) Install and build Go QUIC
/// 2) Create a new file in the `example` directory with the following contents
///    ```
///    package main
///
///    import (
///             "context"
///             "crypto/tls"
///             "fmt"
///             "strconv"
///             "io"
///             "github.com/quic-go/quic-go/internal/utils"
///             "github.com/quic-go/quic-go"
///    )
///
///    const addr = "127.0.0.1:4242"
///
///    func main() {
///             logger := utils.DefaultLogger
///             logger.SetLogLevel(utils.LogLevelDebug)
///
///             tlsConf := &tls.Config{
///                     InsecureSkipVerify: true,
///                     NextProtos:         []string{"quic-echo-example"},
///             }
///             conn, err := quic.DialAddr(addr, tlsConf, nil)
///             if err != nil {
///                    fmt.Println("Error dialing address:", err)
///                    return
///             }
///
///             for i := 0; i < 200; i++ {
///                    message := "Hello swift-quic! Stream[" + strconv.Itoa(i) + "]"
///                    stream, err := conn.OpenStreamSync(context.Background())
///                    if err != nil {
///                            fmt.Println("Error accepting stream:", err)
///                            return
///                    }
///
///
///                    fmt.Printf("Client: Sending '%s'\n", message)
///                    _, err = stream.Write([]byte(message))
///                    if err != nil {
///                            fmt.Println("Error writing to stream:", err)
///                            return
///                    }
///
///                    buf := make([]byte, len(message))
///                    _, err = io.ReadFull(stream, buf)
///                    if err != nil {
///                            fmt.Println("Error reading from stream:", err)
///                            return
///                    }
///
///                    fmt.Printf("Client: Got '%s'\n", buf)
///             }
///
///             return
///    }
///    ```
/// 3) Build the executable
/// 4) Run this test
/// 5) Execute the Go code
/// - Note: Make sure to comment out / remove the XCTSkip line in the test before running it
final class QUICExternalDialServerTests: XCTestCase {
    var group: MultiThreadedEventLoopGroup!
    var server: DatagramBootstrap!
    var channel: Channel!
    fileprivate var serverErrorHandler: ErrorEventLogger!
    fileprivate var serverQuiesceEventRecorder: QuiesceEventRecorder!

    override func setUp() {
        // Configure Server TLS
        var serverConfiguration = TLSConfiguration.makeServerConfiguration(
            certificateChain: try! NIOSSLCertificate.fromPEMBytes(Array(TestConstants.CERT.utf8)).map { .certificate($0) },
            privateKey: .privateKey(try! NIOSSLPrivateKey(bytes: Array(TestConstants.PRIVATE_KEY.utf8), format: .pem))
        )
        serverConfiguration.minimumTLSVersion = .tlsv13
        serverConfiguration.applicationProtocols = ["quic-echo-example"]
        serverConfiguration.renegotiationSupport = .none
        serverConfiguration.certificateVerification = .none

        // Generate our Server SSLContext
        let sslServerContext = try! NIOSSLContext(configuration: serverConfiguration)

        // Configure our Handlers
        self.serverQuiesceEventRecorder = QuiesceEventRecorder()
        self.serverErrorHandler = ErrorEventLogger()

        // Configure Client Channel
        self.group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        self.server = DatagramBootstrap(group: self.group)
            .channelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .channelInitializer { channel in
                channel.pipeline.addHandlers([
                    QuicConnectionMultiplexer(channel: channel, tlsContext: sslServerContext, idleTimeout: .milliseconds(500), inboundConnectionInitializer: nil),
                    self.serverQuiesceEventRecorder,
                    self.serverErrorHandler
                ])
            }
    }

    override func tearDown() {
        if let channel = self.channel {
            try? channel.close(mode: .all).wait()
            self.channel = nil
        }

        self.serverQuiesceEventRecorder = nil
        self.serverErrorHandler = nil

        self.server = nil

        try! self.group.syncShutdownGracefully()
        self.group = nil
    }

    /// This test asserts that when we initialize a QUIC Client Channel, BoringSSL generates and write the client hello crypto frame upon channel activation.
    ///
    /// Takes about 5ms to generate a Client InitialPacket
    /// - Without StreamMuxer
    ///     - 10,000 Synchronous Echo Streams 10.1mb (no memory leak)
    /// - With StreamMuxer
    ///     - 10,000 Synchronous Echo Streams 15+mb and slow (mucho memory leak)
    func testHandshake() throws {
        throw XCTSkip("This integration test is skipped by default")

        // Bind to our UDP port (this activates the Handlers and kicks off a connection)
        self.channel = try! self.server.bind(host: "127.0.0.1", port: 4242).wait()

        // TODO: Figure out how to timeout here...
        try self.channel.closeFuture.wait()
    }
}
