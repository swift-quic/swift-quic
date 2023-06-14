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
///             "io"
///             "github.com/quic-go/quic-go/internal/utils"
///             "github.com/quic-go/quic-go"
///    )
///
///    const addr = "127.0.0.1:4242"
///
///    const message = "Hello swift-quic!"
///
///    func main() {
///            logger := utils.DefaultLogger
///            logger.SetLogLevel(utils.LogLevelDebug)
///
///            tlsConf := &tls.Config{
///                     InsecureSkipVerify: true,
///                     NextProtos:         []string{"quic-echo-example"},
///             }
///             conn, err := quic.DialAddr(addr, tlsConf, nil)
///             if err != nil {
///                    fmt.Println("Error dialing address:", err)
///                    return
///             }
///
///             stream, err := conn.OpenStreamSync(context.Background())
///             if err != nil {
///                    fmt.Println("Error accepting stream:", err)
///                    return
///             }
///
///             fmt.Printf("Client: Sending '%s'\n", message)
///             _, err = stream.Write([]byte(message))
///             if err != nil {
///                    fmt.Println("Error writing to stream:", err)
///                    return
///             }
///
///             buf := make([]byte, len(message))
///             _, err = io.ReadFull(stream, buf)
///             if err != nil {
///                    fmt.Println("Error reading from stream:", err)
///                    return
///             }
///             fmt.Printf("Client: Got '%s'\n", buf)
///
///             return
///    }
///    ```
/// 3) Build the executable
/// 4) Run this test
/// 5) Execute the Go code
///
final class QUICExternalDialServerTests: XCTestCase {
    var group: MultiThreadedEventLoopGroup!
    var server: DatagramBootstrap!
    var channel: Channel!
    fileprivate var serverErrorHandler: ErrorEventLogger!
    fileprivate var serverQuiesceEventRecorder: QuiesceEventRecorder!

    fileprivate let cert = """
    -----BEGIN CERTIFICATE-----
    MIIDXzCCAkegAwIBAgIBATANBgkqhkiG9w0BAQsFADBFMRcwFQYDVQQDDA5xdWlj
    LWRlbW8tY2VydDELMAkGA1UEBhMCVVMxHTAbBgkqhkiG9w0BCQEWDnRvbXMuMjBA
    bWUuY29tMB4XDTIyMTIwMTE5MTAyOFoXDTIzMTIwMTE5MTAyOFowRTEXMBUGA1UE
    AwwOcXVpYy1kZW1vLWNlcnQxCzAJBgNVBAYTAlVTMR0wGwYJKoZIhvcNAQkBFg50
    b21zLjIwQG1lLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK7F
    AZiY/gfS8NOPBF2Zb6ZP7a919drlh5uaKjEipCV1wTuvgtdVoUDmTJr5XlZ8Z6sq
    hXsCUYQu9drii6fUeyB68Bu/WdOpItXuRjemfiijUI3H6x4dImP3y38M3RqCXcbG
    +xtKT63zpQeFC5F3x/wQEFCqeB0sVhm4ZKAgWRHLzY9OGOp0+0SeVnlc4p8w/aKe
    ocqbeVxqI7XFEjhhcZyYU23JeNAoYo2OxJBhjuwHxHrr9FvtbaALDAynDfjxyIL5
    umNi/CMxn2uhzZqtvl4bfEuIREoTEsR97MphUuq80CxqbpUeQiIpiQsYqOTa80or
    xp6w3SUBkV+WpyU+lE8CAwEAAaNaMFgwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8B
    Af8EBAMCAqQwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwEwHQYDVR0OBBYEFKz4Jv3j
    xQFTYrlBhlq9fnGTv5RgMA0GCSqGSIb3DQEBCwUAA4IBAQBrlzxp8xH0qe99rDMe
    AyYnbZuaYkAlHkH2ohtTRMvRxaZPhdqqkOEuTefyT3bBzdSMDixh1ZAPZ08AdYyQ
    4/xW/BMLuvRtnB2qYoG25ql8ASLRjul8SVZ56qmuOcu2FtioZjFD0EDecKBq6Iel
    DMQH8zT6txageTuFz3RSdYk70EKQ6E1F+nOUWlW5qxJAAfNhS0ZxIf58njrhn4nj
    1DM2UCfxe2i/tjGUVGoR83zOq8xvUe38WU+8eSddK5WtTfhKRonuywHTQIVhBQlY
    Y0j95Jvnp03KE8vtRGO1K0DCyseF3F2eqswODCtfjjBW99A+VZ6su7Hqlm/CViaR
    NXab
    -----END CERTIFICATE-----
    """

    fileprivate let privKey = """
    -----BEGIN PRIVATE KEY-----
    MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCuxQGYmP4H0vDT
    jwRdmW+mT+2vdfXa5YebmioxIqQldcE7r4LXVaFA5kya+V5WfGerKoV7AlGELvXa
    4oun1HsgevAbv1nTqSLV7kY3pn4oo1CNx+seHSJj98t/DN0agl3GxvsbSk+t86UH
    hQuRd8f8EBBQqngdLFYZuGSgIFkRy82PThjqdPtEnlZ5XOKfMP2inqHKm3lcaiO1
    xRI4YXGcmFNtyXjQKGKNjsSQYY7sB8R66/Rb7W2gCwwMpw348ciC+bpjYvwjMZ9r
    oc2arb5eG3xLiERKExLEfezKYVLqvNAsam6VHkIiKYkLGKjk2vNKK8aesN0lAZFf
    lqclPpRPAgMBAAECggEAK2VNlSeABE9TbySW7+rWd1Rnb2b56iWOO4vXKCYy3f5U
    Qc69zVw80xGcOerriswPLcg8JqQXu5uxfm08QisXe6QrFKi51D2uIbKtisnzj4Gl
    0d6vOeYAERSJWf3GtPtj76Se21LjYA0ckDZv/enhJWyTsIPzmULWCkLn8X62vx0T
    w0KtkOLABW6+b+i2TAQoBrJkrrWuGwo5N8K4dvFW64aouJVb+XxzSdCSeakJOGev
    wGDAMDKSFo7ho5MPjIRRBpuLtpONhXpUXSYBISTr6Nwi/Vw7sa/HXU0OVARjOjyL
    snb1eXvBEXxvGqNDxUMhgJTSXi/UKSydz2UE8CgQ4QKBgQDdDfmaJNkye6RJYwqK
    jNPX/Jmf8Zb5EBQrPK7A4Tq2IakwOTzJZs4ZQConN4QI+CFezHVtRU0lEjjvdiYw
    I+JUgAzyaSdG8IRlu1UCtPNyqkW8nkXu9rQkTputpcv6v5B1Lfx8q5hoEyM56g4M
    hVT/tXOwULeqSjWPbuA+d8Wj3wKBgQDKZeMi2/FBZW5XTGuTAapfasyeiFsnUyR1
    kh35uIhpcS/qkVlQFKGl+Q7niJpFytuWToom2+90ueq2d5BoSuRbGAMRWP7/g3Hn
    b7tVgYhQzY4sI2JQk3QvHbOfw96+fiUqysnBY5ioeA526cE/gFdDjJCmG1ia70x0
    x9g1+NOdkQKBgC3UHuJRL2Ji9c1tJhtRVP4bVXIucQFTzwqjuwsr5rMpyVzBERQk
    JyhfAB4/STVe0/RGaTXtPzAnVfx3PzWNyvd/0K9VE5qGdLxumRJFl483M9wF6DPB
    m9lHHslibSagHn/ct9LU9HTnOs9f8eewoM2evcxY/6rjVbVV5FGvHR97AoGAatVn
    FEJmUS+aE6h56+noJV95TIELJHHFf+21ttfJ4WZmdXltXFDXloUlcd9wF0DhsbAZ
    SjOzbLiqBNCNwA8wBEljbSe9yd93I0Od7Z9m9cfasL+oqIF8xVX3N3CrRX/OXI0X
    ++V3cg2VDP2MDNnQtg4fWB59IaMIh2fpX2vNP5ECgYEAqpjGiLPJq+S39sJ0WASZ
    GTAbqRMyScBLODwZlKjuCYt1HUFyu6D/HCwdNxRdKdW0vMUsCxadICmy68ogbyK6
    BD4ObB5VW9Xd8s9Bpdkt8TQ+3zp+vSkezvFDZ0eQFGIGmRRxbNUoMiLjGWCKAp/5
    27zXnvbAtjbahJNQIClIM+c=
    -----END PRIVATE KEY-----
    """

    override func setUp() {
        // Configure Server TLS
        var serverConfiguration = TLSConfiguration.makeServerConfiguration(
            certificateChain: try! NIOSSLCertificate.fromPEMBytes(Array(self.cert.utf8)).map { .certificate($0) },
            privateKey: .privateKey(try! NIOSSLPrivateKey(bytes: Array(self.privKey.utf8), format: .pem))
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
                    QuicConnectionMultiplexer(channel: channel, tlsContext: sslServerContext, inboundConnectionInitializer: nil),
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
    /// Takes about 5ms to generate a Client InitialPacket
    func testHandshake() throws {
        throw XCTSkip("This integration test is skipped by default")
        
        // Bind to our UDP port (this activates the Handlers and kicks off a connection)
        self.channel = try! self.server.bind(host: "127.0.0.1", port: 4242).wait()

        // TODO: Figure out how to timeout here...
        try self.channel.closeFuture.wait()
    }
}
