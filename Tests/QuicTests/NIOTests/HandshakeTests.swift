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

// MARK: QuiesceEventRecorder Helper Handler

internal final class QuiesceEventRecorder: ChannelInboundHandler {
    typealias InboundIn = Any
    typealias InboundOut = Any

    public var quiesceCount = 0

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if event is ChannelShouldQuiesceEvent {
            self.quiesceCount += 1
        }
        context.fireUserInboundEventTriggered(event)
    }
}

// MARK: ErrorEventLogger Helper Handler

internal final class ErrorEventLogger: ChannelDuplexHandler {
    typealias InboundIn = Any
    typealias InboundOut = Any
    typealias OutboundIn = Any
    typealias OutboundOut = Any

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        print(error)
        context.fireErrorCaught(error)
    }
}

struct TestConstants {
    static let CERT: String = """
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

    static let PRIVATE_KEY = """
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
}

final class QUICHandshakeTests: XCTestCase {
    var backToBack: BackToBackEmbeddedChannel!
    var clientInitialBytes: ByteBuffer?
    let version: Version = .version1
    var dcid: ConnectionID!
    var scid: ConnectionID!
    fileprivate var quicClientHandler: QUICStateHandler!
    fileprivate var clientErrorHandler: ErrorEventLogger!
    fileprivate var clientQuiesceEventRecorder: QuiesceEventRecorder!

    fileprivate var quicServer: QuicConnectionMultiplexer!
    fileprivate var serverErrorHandler: ErrorEventLogger!
    fileprivate var serverQuiesceEventRecorder: QuiesceEventRecorder!

    override func setUp() {
        // Configure QUIC Params
        var clientParams = TransportParams.default
        self.scid = ConnectionID(with: try! Array(hexString: "0123456789"))
        self.dcid = ConnectionID(randomOfLength: 18)
        clientParams.initial_source_connection_id = self.scid

        // Configure Client TLS
        var configuration = TLSConfiguration.makeClientConfiguration()
        configuration.minimumTLSVersion = .tlsv13
        configuration.maximumTLSVersion = .tlsv13
        configuration.applicationProtocols = ["echo"]
        configuration.renegotiationSupport = .none
        configuration.certificateVerification = .none

        // Generate our Client SSLContext
        let sslClientContext = try! NIOSSLContext(configuration: configuration)

        // Client QUIC State Handler
        let clientHandler = try! QUICStateHandler(SocketAddress(ipAddress: "127.0.0.1", port: 0), perspective: .client, versions: [self.version], destinationID: self.dcid, sourceID: self.scid, tlsContext: sslClientContext, idleTimeout: .milliseconds(200))

        // Configure Server TLS
        var serverConfiguration = TLSConfiguration.makeServerConfiguration(
            certificateChain: try! NIOSSLCertificate.fromPEMBytes(Array(TestConstants.CERT.utf8)).map { .certificate($0) },
            privateKey: .privateKey(try! NIOSSLPrivateKey(bytes: Array(TestConstants.PRIVATE_KEY.utf8), format: .pem))
        )
        serverConfiguration.minimumTLSVersion = .tlsv13
        serverConfiguration.applicationProtocols = ["h3", "test", "echo"]
        serverConfiguration.renegotiationSupport = .none
        serverConfiguration.certificateVerification = .none

        // Generate our Server SSLContext
        let sslServerContext = try! NIOSSLContext(configuration: serverConfiguration)

        self.backToBack = BackToBackEmbeddedChannel()

        // Configure Client Channel
        self.quicClientHandler = clientHandler
        self.clientQuiesceEventRecorder = QuiesceEventRecorder()
        self.clientErrorHandler = ErrorEventLogger()
        XCTAssertNoThrow(try self.backToBack.client.pipeline.addHandler(self.quicClientHandler).wait())
        XCTAssertNoThrow(try self.backToBack.client.pipeline.addHandler(self.clientErrorHandler).wait())
        XCTAssertNoThrow(try self.backToBack.client.pipeline.addHandler(self.clientQuiesceEventRecorder).wait())

        // Configure Server Channel
        // TODO: We should install our Muxer here instead of the UDPClientHandler
        self.quicServer = QuicConnectionMultiplexer(channel: self.backToBack.server, tlsContext: sslServerContext, idleTimeout: .zero, inboundConnectionInitializer: nil)
        self.serverQuiesceEventRecorder = QuiesceEventRecorder()
        self.serverErrorHandler = ErrorEventLogger()
        XCTAssertNoThrow(try self.backToBack.server.pipeline.addHandler(self.quicServer).wait())
        XCTAssertNoThrow(try self.backToBack.server.pipeline.addHandler(self.serverErrorHandler).wait())
        XCTAssertNoThrow(try self.backToBack.server.pipeline.addHandler(self.serverQuiesceEventRecorder).wait())

        // Activate our Server Channel
        // Note `.bind` doesn't activate the channel
        XCTAssertNoThrow(try self.backToBack.server.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 0)).wait())

        // Activate our Client Channel
        XCTAssertNoThrow(try self.backToBack.client.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 0)).wait())
    }

    override func tearDown() {
        XCTAssertNoThrow(try self.backToBack.client.finish(acceptAlreadyClosed: true))
        XCTAssertNoThrow(try self.backToBack.server.finish(acceptAlreadyClosed: true))
        self.backToBack = nil
        self.clientInitialBytes = nil

        self.quicClientHandler = nil
        self.clientQuiesceEventRecorder = nil
        self.clientErrorHandler = nil

        self.quicServer = nil
        self.serverQuiesceEventRecorder = nil
        self.serverErrorHandler = nil
    }

    /// This test asserts that when we initialize a QUIC Client Channel, BoringSSL generates and write the client hello crypto frame upon channel activation.
    /// Takes about 5ms to generate a Client InitialPacket
    func testHandshake() throws {
        try self.backToBack.interactInMemory(for: .seconds(1), withTimeStep: .microseconds(10))

        // Close our embedded channels
        try? self.backToBack.client.close(mode: .all).wait()
        try self.backToBack.server.close(mode: .all).wait()
    }
}

/// swift-nio-ssl
/// BackToBackEmbeddedChannel
///
/// Example Usage
/// ```
/// let dummyAddress = try! SocketAddress(ipAddress: "1.2.3.4", port: 5678)
/// let backToBack = BackToBackEmbeddedChannel()
/// let serverHandler = NIOSSLServerHandler(context: serverContext)
/// let clientHandler = try! NIOSSLClientHandler(context: clientContext, serverHostname: "localhost")
/// try! backToBack.client.pipeline.addHandler(clientHandler).wait()
/// try! backToBack.server.pipeline.addHandler(serverHandler).wait()
///
/// // To trigger activation of both channels we use connect().
/// try! backToBack.client.connect(to: dummyAddress).wait()
/// try! backToBack.server.connect(to: dummyAddress).wait()
///
/// try! backToBack.interactInMemory()
/// ```
final class BackToBackEmbeddedChannel {
    typealias DataType = AddressedEnvelope<ByteBuffer>
    private(set) var client: EmbeddedChannel
    private(set) var server: EmbeddedChannel
    private(set) var loop: EmbeddedEventLoop

    init() {
        self.loop = EmbeddedEventLoop()
        self.client = EmbeddedChannel(loop: self.loop)
        self.server = EmbeddedChannel(loop: self.loop)
    }

    func run() {
        self.loop.run()
    }

    func interactInMemory() throws {
        var workToDo = true

        while workToDo {
            workToDo = false

            self.loop.run()
            let clientDatum = try self.client.readOutbound(as: DataType.self)
            let serverDatum = try self.server.readOutbound(as: DataType.self)

            // Reads may trigger errors. The write case is automatic.
            try self.client.throwIfErrorCaught()
            try self.server.throwIfErrorCaught()

            if let clientMsg = clientDatum {
                try self.server.writeInbound(clientMsg)
                workToDo = true
            }

            if let serverMsg = serverDatum {
                try self.client.writeInbound(serverMsg)
                workToDo = true
            }
        }
    }

    /// This helps get around our issue where we need to yeild to NIOSSL while it's generating keys...
    func interactInMemory(for totalTime: TimeAmount, withTimeStep: TimeAmount = .microseconds(10)) throws {
        guard withTimeStep < totalTime else { throw Errors.InvalidState }
        let timestep = withTimeStep
        var now: NIODeadline = .uptimeNanoseconds(0)

        while now.uptimeNanoseconds < totalTime.nanoseconds {
            self.loop.advanceTime(by: timestep)
            now = now + timestep

            self.loop.run()
            let clientDatum = try self.client.readOutbound(as: DataType.self)
            let serverDatum = try self.server.readOutbound(as: DataType.self)

            // Reads may trigger errors. The write case is automatic.
            try self.client.throwIfErrorCaught()
            try self.server.throwIfErrorCaught()

            if let clientMsg = clientDatum {
                try self.server.writeInbound(clientMsg)
            }

            if let serverMsg = serverDatum {
                try self.client.writeInbound(serverMsg)
            }
        }
    }
}
