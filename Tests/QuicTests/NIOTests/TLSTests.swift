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

final class TLSClientInitialTests: XCTestCase {
    var channel: EmbeddedChannel!
    var clientInitialBytes: ByteBuffer?
    let version: Version = .version2
    var dcid: ConnectionID!
    var scid: ConnectionID!
    fileprivate var quicClientHandler: QUICStateHandler!
    fileprivate var errorHandler: ErrorEventLogger!
    fileprivate var tlsHandler: NIOSSLClientHandler!
    fileprivate var quiesceEventRecorder: QuiesceEventRecorder!

    var expectedQuicParams: [UInt8] = []

    override func setUp() {
        var configuration = TLSConfiguration.makeClientConfiguration()
        configuration.minimumTLSVersion = .tlsv13
        configuration.maximumTLSVersion = .tlsv13
        configuration.applicationProtocols = ["h3"]
        self.scid = ConnectionID(with: try! Array(hexString: "0123456789"))
        self.dcid = ConnectionID(randomOfLength: 18)
        var params = TransportParams.default
        params.initial_source_connection_id = self.scid
        //configuration.quicParams = try! Array(params.encode(perspective: .client).readableBytesView)
        self.expectedQuicParams = try! Array(params.encode(perspective: .client).readableBytesView)

        let sslContext = try! NIOSSLContext(configuration: configuration)

        self.channel = EmbeddedChannel()
        self.quicClientHandler = try! QUICStateHandler(SocketAddress(ipAddress: "127.0.0.1", port: 0), perspective: .client, version: self.version, destinationID: self.dcid, sourceID: self.scid, tlsContext: sslContext)
        self.tlsHandler = try! NIOSSLClientHandler(context: sslContext, serverHostname: nil)
        self.quiesceEventRecorder = QuiesceEventRecorder()
        self.errorHandler = ErrorEventLogger()
        XCTAssertNoThrow(try self.channel.pipeline.addHandler(self.quicClientHandler).wait())
        XCTAssertNoThrow(try self.channel.pipeline.addHandler(self.tlsHandler).wait())
        XCTAssertNoThrow(try self.channel.pipeline.addHandler(self.errorHandler).wait())
        XCTAssertNoThrow(try self.channel.pipeline.addHandler(self.quiesceEventRecorder).wait())

        // this activates the channel
        XCTAssertNoThrow(try self.channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 1)).wait())
    }

    override func tearDown() {
        if let channel = self.channel {
            XCTAssertNoThrow(try channel.finish(acceptAlreadyClosed: true))
            self.channel = nil
        }
        self.clientInitialBytes = nil
        self.quicClientHandler = nil
        self.tlsHandler = nil
        self.quiesceEventRecorder = nil
    }

    /// This test asserts that when we initialize a QUIC Client Channel, BoringSSL generates and write the client hello crypto frame upon channel activation.
    /// Takes about 5ms to generate a Client InitialPacket
    func testGenerateClientHello() throws {
        // This is set to v1.2 for historical reasons, v1.3 (which will be enforced) is specified in the `tls version` within the client hello
        XCTAssertEqual(self.tlsHandler.tlsVersion, NIOSSL.TLSVersion.tlsv12)
        self.expectedQuicParams = self.quicClientHandler.ourParams
        let addressedEnvelope = try self.channel.readOutbound(as: AddressedEnvelope<ByteBuffer>.self)
        self.clientInitialBytes = addressedEnvelope?.data
        if let readableBytes = clientInitialBytes?.readableBytes, let buf = clientInitialBytes?.readBytes(length: readableBytes) {
            print(buf.hexString)

            // Attempt to decrypt it (as the server)
            let initialKeys = try version.newInitialAEAD(connectionID: self.dcid, perspective: .server)
            let decrypted = try initialKeys.open(bytes: buf, packetNumberOffset: buf.calculateLongHeaderPacketNumberOffset())

            var cryptoFrame = Array(decrypted.payload.drop(while: { $0 == 0x00 }))
            guard let clientHello = try? ClientHello(fromCryptoFrame: &cryptoFrame) else {
                return XCTFail("BoringSSL Generated an Invalid ClientHello")
            }
            XCTAssertEqual(clientHello.tlsVersion, [0x03, 0x03])
            XCTAssertEqual(clientHello.cipherSuites, [[0x13, 0x01], [0x13, 0x02], [0x13, 0x03]])

            XCTAssertEqual(clientHello.extensions.first(whereType: .supported_groups)?.value, [0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18])
            XCTAssertEqual(clientHello.extensions.first(whereType: .application_layer_protocol_negotiation)?.value, [0x00, 0x03, 0x02, 0x68, 0x33])
            XCTAssertEqual(clientHello.extensions.first(whereType: .signature_algorithms)?.value, [0x00, 0x12, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01])
            XCTAssertTrue( clientHello.extensions.contains(type: .key_share))
            XCTAssertEqual(clientHello.extensions.first(whereType: .psk_key_exchange_modes)?.value, [0x01, 0x01])
            XCTAssertEqual(clientHello.extensions.first(whereType: .supported_versions)?.value, [0x02, 0x03, 0x04])
            XCTAssertEqual(clientHello.extensions.first(whereType: .quic_transport_parameters)?.value, self.expectedQuicParams)

            /// Ensure there's no additional unexpected / unconsumed data
            XCTAssertEqual(cryptoFrame.count, 0)

        } else {
            XCTFail("No Output data...")
        }

        /// Ensure there's no additional unexpected / unconsumed data
        XCTAssertEqual(self.clientInitialBytes?.readableBytes, 0)

        try self.channel.close(mode: .all).wait()
    }
}
