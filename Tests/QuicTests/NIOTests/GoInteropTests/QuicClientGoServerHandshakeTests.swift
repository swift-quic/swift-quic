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

/// Swift QUIC Client <-> Go Server Handshake Test
///
/// This test is meant to be run in conjunction with a Go QUIC Server that accepts our connection, accepts our stream, and echos back a string that we send.
///
/// Usage:
/// 1) Install and build Go QUIC
/// 2) Create a new file in the `example` directory with the following contents
///    ```
///    package main
///
///    import (
///            "context"
///            "crypto/rand"
///            "crypto/rsa"
///            "crypto/tls"
///            "crypto/x509"
///            "encoding/pem"
///            "fmt"
///            "io"
///            "math/big"
///            "github.com/quic-go/quic-go"
///            "github.com/quic-go/quic-go/internal/utils"
///    )
///
///    const addr = "127.0.0.1:6120"
///
///    const message = "foobar"
///
///    func main() {
///        logger := utils.DefaultLogger
///        logger.SetLogLevel(utils.LogLevelDebug)
///
///        // Set up a QUIC listener
///        quicConfig := &quic.Config{}
///        listener, err := quic.ListenAddr("127.0.0.1:4242", generateTLSConfig(), quicConfig)
///        if err != nil {
///            panic(err)
///        }
///
///        fmt.Println("Listening on", listener.Addr())
///
///        // Wait for incoming connections
///        for {
///            conn, err := listener.Accept(context.Background())
///            if err != nil {
///                fmt.Println("Error accepting session:", err)
///                continue
///            }
///
///            // Handle incoming connections in separate goroutines
///            fmt.Println("Accepted connection:", conn.RemoteAddr())
///
///            // Accept the first stream opened by the client
///            stream, err := conn.AcceptStream(context.Background())
///            if err != nil {
///                fmt.Println("Error accepting stream:", err)
///                return
///            }
///
///            fmt.Println("Accepted stream:", stream.StreamID())
///
///            // Echo through the loggingWriter
///            _, err = io.Copy(loggingWriter{stream}, stream)
///            if err != nil {
///                    fmt.Println("Error Echoing Stream Data:", err)
///            }
///        }
///    }
///
///    func handleConnection(conn quic.Connection) {
///        fmt.Println("Accepted connection:", conn.RemoteAddr())
///
///        // Accept the first stream opened by the client
///        stream, err := conn.AcceptStream(context.Background())
///        if err != nil {
///            fmt.Println("Error accepting stream:", err)
///            return
///        }
///
///        fmt.Println("Accepted stream:", stream.StreamID())
///
///        // Echo back all data received on the stream
///        buf := make([]byte, 1024)
///        for {
///            n, err := stream.Read(buf)
///            if err != nil {
///                fmt.Println("Error reading from stream:", err)
///                return
///            }
///
///            fmt.Println("Received data:", string(buf[:n]))
///
///            if _, err := stream.Write(buf[:n]); err != nil {
///                fmt.Println("Error writing to stream:", err)
///                return
///            }
///        }
///    }
///
///    // A wrapper for io.Writer that also logs the message.
///    type loggingWriter struct{ io.Writer }
///
///    func (w loggingWriter) Write(b []byte) (int, error) {
///            fmt.Printf("Server: Got '%s'\n", string(b))
///            return w.Writer.Write(b)
///    }
///
///    // Setup a bare-bones TLS config for the server
///    func generateTLSConfig() *tls.Config {
///            key, err := rsa.GenerateKey(rand.Reader, 1024)
///            if err != nil {
///                    panic(err)
///            }
///            template := x509.Certificate{SerialNumber: big.NewInt(1)}
///            certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
///            if err != nil {
///                    panic(err)
///            }
///            keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
///            certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
///
///            tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
///            if err != nil {
///                    panic(err)
///            }
///            return &tls.Config{
///                    Certificates: []tls.Certificate{tlsCert},
///                    NextProtos:   []string{"quic-echo-example"},
///            }
///    }
///
///    ```
/// 3) Build the executable
/// 4) Execute the Go code
/// 5) Run `testHandshake2` test pointed at port 4242
///
final class QUICExternalDialClientTests: XCTestCase {
    var group: MultiThreadedEventLoopGroup!
    var client: DatagramBootstrap!
    var channel: Channel!
    let version: Version = .version1
    var dcid: ConnectionID!
    var scid: ConnectionID!
    fileprivate var quicClientHandler: QUICStateHandler!

    override func setUp() {
        // Configure QUIC Params
        self.scid = ConnectionID(randomOfLength: 0)
        self.dcid = ConnectionID(randomOfLength: 12)

        // Configure Client TLS
        var configuration = TLSConfiguration.makeClientConfiguration()
        configuration.minimumTLSVersion = .tlsv13
        configuration.maximumTLSVersion = .tlsv13
        configuration.applicationProtocols = ["quic-echo-example"] //["h3"]
        configuration.renegotiationSupport = .none
        configuration.certificateVerification = .none

        // Generate our Client SSLContext
        let sslClientContext = try! NIOSSLContext(configuration: configuration)

        // Configure our Handlers
        self.quicClientHandler = try! QUICStateHandler(SocketAddress(ipAddress: "127.0.0.1", port: 4242), perspective: .client, version: self.version, destinationID: self.dcid, sourceID: self.scid, tlsContext: sslClientContext)

        // Configure Client Channel
        self.group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        self.client = DatagramBootstrap(group: self.group)
            .channelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .channelInitializer { channel in
                channel.pipeline.addHandlers([
                    self.quicClientHandler
                ])
            }
    }

    override func tearDown() {
        if let channel = self.channel {
            try? channel.close(mode: .all).wait()
            self.channel = nil
        }

        self.quicClientHandler = nil

        self.client = nil

        try! self.group.syncShutdownGracefully()
        self.group = nil
    }

    func testHandshake() throws {
        throw XCTSkip("This integration test is skipped by default")

        // Bind to our UDP port (this activates the Handlers and kicks off a connection)
        self.channel = try! self.client.connect(host: "127.0.0.1", port: 4242).wait()

        // TODO: Figure out how to timeout here...
        try self.channel.closeFuture.wait()
    }
}
