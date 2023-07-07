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

//TLSHandshakePipelineHandlerEmbeddedParamsTest
final class PacketProtectorHandlerTests: XCTestCase {
    var channel: EmbeddedChannel!
    fileprivate var odcid: ConnectionID = ConnectionID(with: [142, 80, 168, 127, 165, 188, 21, 215, 67, 168, 192, 86, 106, 234, 144, 0, 208, 99])
    fileprivate var scid: ConnectionID = ConnectionID(with: [1, 35, 69, 103, 137])
    fileprivate var packetProtectorHandler: PacketProtectorHandler!

    override func setUp() {
        self.channel = EmbeddedChannel()
        self.packetProtectorHandler = try! PacketProtectorHandler(initialDCID: self.odcid, scid: self.scid, versions: [.version1], perspective: .client, remoteAddress: SocketAddress(ipAddress: "127.0.0.1", port: 1))
        XCTAssertNoThrow(try self.channel.pipeline.addHandler(self.packetProtectorHandler).wait())

        // this activates the channel
        //XCTAssertNoThrow(try self.channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 1)).wait())
    }

    override func tearDown() {
        if let channel = self.channel {
            XCTAssertNoThrow(try channel.finish(acceptAlreadyClosed: true))
            self.channel = nil
        }
        self.packetProtectorHandler = nil
    }

    func testProcessInboundDatagrams() throws {
        // Construct the first datagram
        let firstDatagram = try ByteBuffer(hexString: "c00000000105012345678904869e84be004075dd34b0a68708bee2075c762a7ed017e61c6e673e82a0cab0651c14a5143735b1c70d796569d729b68c0b206125260b6f92bf17422cf11ef949bcb728746dbb7f25dc44b8bd3a2233c0e20725fc87664668ac9a2514900ac150f1a4c01949d4afc94d45ed9b975bf9b634560cf7366640d1ea0d0eb2ea0000000105012345678904869e84be444afb86ca98de96829e13f62768c76b85fadc57565abc8b3820af1fc55c1fe424e337b6d89e7e3ccb37de41224c99c16bb754455db93a77289060920d2a2bd866926410ef42201f0ee599a79334010f4d336568be2dbf205aeda1ac767d9493845e6fa509079ab5f16dc7878e0e72851f118a68e6852b482d320beb5dcb189c5a57231cfd54e30adcf137129b15605b9b90036b1eef4509c1d6314f531cccfd5db4bbb603aca215026f43e2ab423f13294b11615eab3a5a8d43f19778dd6493ac3273de99456c32f8e514c202621d8b80edf9655b4e7932c7ea8ea27f36d96cc2cb53afa6f0903504c47727575760164314f0108f4bf1a0edb93e754f6c175b0f263f2337e634d7b9d419646a1896aba78fb9791c87df5b80bee53cd4fa3487b750935aefac1f93fb77fa5426d20f136ad8f7b477e9e0f3329335a10312f6e50eb0c10a6c371814eac79fd33e8e4f568bc9aa7a30b4372c53e0a1dc156172d54ba9cbdb607f8e4ab58685be3c97607e4581cdbf2eb823d7d7e5fb3a56e8d6e154904d7ded8f89db2613d3dc54b2f4299e36134e95b88bec8f56851a4d8d3b0922da05f9dfac4cdc5ce03bc83823dcfea94d3d80bfb835b8c7fb02671934fa996de7a2d3b3b22c1ed8517b9f0980ba49dc7f614c85d7b525257461907c197318010a229dcf63015bfe65003c11ad3f626da65d31dd35ca3862eddb17e54e9c956a67c5960fc8fff8505ece778979ae94219313c992dbd23d92531b011b6e54e0623076eeb351ed80dd1d7946296abf642b71e90aa26f499742ac08c4eb1a744fe137442ea79e389e6ca0ba609a9c7ca26fbe62772d532ee819f4d0fb5d03687b7c026917ed6267bfcdc82070179dc6cc9fab6fd56ce84160c9b068bf73306560cf98caab9b16b8cc23234f9278dd5f097a2e4bde04caf745dc0faec4ad2c4468e5cf86f06fa62f6f53181de396972614b22c5cc2a25251b09d9d1a84240b5d4bd2f3fbc13446f6414d09d1f8ba6d801d17c3eb1147fb605084eb674edf982ff0c28a6265099f414acfd9cebc8d920a995400136c23c6f47df7213f776f6b055375f7f2204bd10bbf158d9f64ce8dff6bf99efea491fb9433193332f010042f06cb8709add76a681f215c992b7282f18b4c575c4066ae4dc1a1cddd7ccfd9f7ea863929b9f176f6aed332516d126c9f2ef7c73d8780bbdf9ec6ee9f005118878e4d8479d208cb54391e5299131dcfcc02e4c6f7b63c253f318cd5da52698cd5d80f98e57aabab35ccf6b6935a3e9db6b2b64bb80f995783e9008a84b9dd9e2f6d74ff338db005e3219f084f2276e5599c39043921bf7473b152c89daed0cd657b4c41325e53486ec4775cb223df4e8765dc4bea3c19a380f6d582c25026a245c5c64ce013b17c71925ddb490116c0064d5ecd0f147c5158f106bda681e53c06935410f05950a3efad22ca692abf69ac872e929d181abb6007a8a65d3df0a03b05fd71042fbf5ae3fc6295390da9998bf6a9b53d656f0029fbacddb024ac9edd4337acb1530118ef86026fed47")

        // Write the first datagram into the PacketProtectorHandler
        XCTAssertNoThrow(try self.channel.writeInbound(firstDatagram))

        // Ensure the initial packet was decrypted and is available
        let initialPacket = try? self.channel.readInbound(as: InitialPacket.self)
        XCTAssertNotNil(initialPacket)
        //print(initialPacket!.payload.hexString)

        // This shouldn't work!
        XCTAssertNil(try? self.channel.readInbound(as: HandshakePacket.self))

        // Allow handshake buffer flushing...
        self.packetProtectorHandler.allowHandshakeFlush()

        // Inject the Handshake Key secret
        // CLIENT_HANDSHAKE_TRAFFIC_SECRET 446e3277f651198a0d814da0ca3060df236c27decc78f0ebb8b309723d1cccf4 9dfffabb0bdb12fc7fa3ca5e06bf8d58f710fe19d10a816d208a467b92001e32
        // SERVER_HANDSHAKE_TRAFFIC_SECRET 446e3277f651198a0d814da0ca3060df236c27decc78f0ebb8b309723d1cccf4 1ea248f609ceadde0d080c4c958706cace5de38e809be2028955ce4077062573
        XCTAssertNoThrow(try self.packetProtectorHandler.installHandshakeKeys(secret: Array(hexString: "1ea248f609ceadde0d080c4c958706cace5de38e809be2028955ce4077062573"), for: .server, cipherSuite: .ChaChaPoly_SHA256))

        // At this point we should now be able to read the buffered handshake packet
        let firstHandshakePacket = try? self.channel.readInbound(as: HandshakePacket.self)
        XCTAssertNotNil(firstHandshakePacket)
        //print(firstHandshakePacket!.payload.hexString)

        XCTAssertNil(try? self.channel.readInbound(as: HandshakePacket.self))

        XCTAssertEqual(self.packetProtectorHandler.encryptedHandshakeBuffer.readableBytes, 0)

        // Read second datagram
    }
}

// These values are borrowed from quic.xargs.org
// These tests focus on our PacketProtectorHandler
// One of the purposes of the PacketProtectorHandler is to buffer inbound Packets from epochs we don't have keys for yet.
final class PacketProtectorHandlerTests2: XCTestCase {
    var channel: EmbeddedChannel!
    fileprivate var odcid: ConnectionID = ConnectionID(with: [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07])
    fileprivate var scid: ConnectionID = ConnectionID(with: [0x63, 0x5f, 0x63, 0x69, 0x64])
    fileprivate var packetProtectorHandler: PacketProtectorHandler!

    //CLIENT_HANDSHAKE_TRAFFIC_SECRET 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f b8902ab5f9fe52fdec3aea54e9293e4b8eabf955fcd88536bf44b8b584f14982
    //SERVER_HANDSHAKE_TRAFFIC_SECRET 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 88ad8d3b0986a71965a28d108b0f40ffffe629284a6028c80ddc5dc083b3f5d1
    //CLIENT_TRAFFIC_SECRET_0         000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f a877a82fd5f89ba622eb03dc5868fd00a31cc2eb8646b362a75bc14893a8ef07
    //SERVER_TRAFFIC_SECRET_0         000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f a1bfa69e7051fd609946fd9431a51992617c4ddb9c1269c9c0b70cc91b297751
    //EXPORTER_SECRET                 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 68a1b3f5586893c5bc0986b9e94fbf11c4129e8e9969e111b4b3dea300df29ca

    let SERVER_HANDSHAKE_SECRET = "88ad8d3b0986a71965a28d108b0f40ffffe629284a6028c80ddc5dc083b3f5d1"
    let SERVER_TRAFFIC_SECRET = "a1bfa69e7051fd609946fd9431a51992617c4ddb9c1269c9c0b70cc91b297751"
    let COMMON = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

    // Contains the `Server Initial Packet` and the first `Server Handshake Packet`
    let firstDatagram = try! ByteBuffer(hexString: "cd0000000105635f63696405735f6369640040753a836855d5d9c823d07c616882ca770279249864b556e51632257e2d8ab1fd0dc04b18b9203fb919d8ef5a33f378a627db674d3c7fce6ca5bb3e8cf90109cbb955665fc1a4b93d05f6eb83252f6631bcadc7402c10f65c52ed15b4429c9f64d84d64fa406cf0b517a926d62a54a9294136b143b033ed0000000105635f63696405735f6369644414b7dd73ae296209dff2d02d3d50af692176dd4d509fe8cb1b46e45b09364d815fa7a5748e2180dad2b7b668cab86fbdc2988c45cbb851ddcf1601b780d748b9ee641ebcbe20126e32267e664d2f37cf53b753d124717c2e13c48a09e3428b11dc73baebd498e8caf5becefea760d0e7a5cdb76b52bcb19229973e5d09aa055e9c9718dc581454775c58ecdd5ee7e77278f5601070404162a79ee8c59645d6ca24a200186ae99ce47eace1cfc9527b24ae8bc6ccdbacb79b81c91a26954707ba35cba0cae9aff418c6e08da6506163a39f19b676a66ac174e3295f1ab9ea7383a9c285d73e95758dc9bd8da90734a9fedfd7e1f74d2b69c70bf739a48c5a5d0afa0bfa1603471b0c61a9cade120b3986a6ce0295be8228c6927013b06da58d31996231b9e3150bb58270960e61cbc6698a2f1379a2258465da7325b349c6cd55d105fd5485fd0ac79a1df1dbba7f85b49b72365bfab9d578e01dcbff8515a632fd7001382ed90f6cdcb17db99a33fa1181f6f61a89e783cfb042fc0f2f67cdb60e89f263885681ae645a1c7ab1590eb2f8469f460f04e09fea2a3a411b498663010b3c382a3f25837c2c7086af5a9ad290cf3ccf1ac6eb0f445535e8b00a557c87a53d93071462a0bc22614e5c3ae08417b720a736c1ad48ea3775cd0f009f0c57500e0bb2e7e9c53f83699a47e5f13bb20772ab23506424b76f6ef96a61c917226e6e048de6f82426ca63eabf3b5943af0b5f0d123d9af045bb357cadbd1092ad0a1d7551162a3b4b486c271e00244b23d8adec81c92e31239c75af41cb079808571b48acb507333ffbf1a486d8053edcc862b6a9bfd36a09cddba3291b9b8ba158493459805ce241daf5c1308599fc0e6e6ea7103033b294cc7a5fdb2d4654f1d4407825ebc375abdfb2cca1abf5a241343dec3b165d320af84bc1fa21112efdb9d45c6cfc7b8a6442ff593d09219336fa0756d9e45bab4fa63394a2a8803df4678e79216fdf131f55822f9ead694ab75ee25496e6b78c3b09046658e2c427ddc4538af8de2acb81398b74828337f269cb031d997a5cf63e11ab050aa8aee1f07962ddd7515ab60e192e403c300311e9e4b9b70f1615029d07fe1c231939027149f4fd2972023a55de29356505fbe749908c62aa33eb259a399bf711b92b616cb748de73c8bfadd5d43e2dae916a7ba0db61dfcd6faf957608262b6834e33185b8d5598f87e6992aacf57696add5558a7d9694381f5d7d659da2de951b607478f61da208a24a07ba8da00258fa7f2fe10def6183267f5d38e04c942300b9c874e8983c1be14e1608ffdca67d7e4513cc0cb9cab81d6319dd1074b217e5195465131e06dd0bafaba84eb52c22a4a8c612a405fe6c874232e4a934611bc73c56fe70b2cb7a596c1f53c729b6643cbd70d530fe3196069fc0078e89fbb70dc1b38ab4e1770c8ffb53316d673a32b89259b5d33e94ad")

    // Contains the second `Server Handshake Packet`
    let secondDatagram = try! ByteBuffer(hexString: "e50000000105635f63696405735f63696440cf4f4420f919681c3f0f102a30f5e647a3399abf54bc8e80453134996ba33099056242f3b8e662bbfce42f3ef2b6ba87159147489f8479e849284e983fd905320a62fc7d67e9587797096ca60101d0b2685d8747811178133ad9172b7ff8ea83fd81a814bae27b953a97d57ebff4b4710dba8df82a6b49d7d7fa3d8179cbdb8683d4bfa832645401e5a56a76535f71c6fb3e616c241bb1f43bc147c296f591402997ed49aa0c55e31721d03e14114af2dc458ae03944de5126fe08d66a6ef3ba2ed1025f98fea6d6024998184687dc06")

    // Contains the third `Server Handshake Packet` and the first `Traffic (or Application) Packet`
    let thirdDatagram = try! ByteBuffer(hexString: "e50000000105635f63696405735f6369644016a4875b25169e6f1b817e4623e1acbe1db3899b00ecfb49635f636964cd9a64124057c883e94d9c296baa8ca0ea6e3a21faaf99af2fe10321692057d2")

    override func setUp() {
        self.channel = EmbeddedChannel()
        self.packetProtectorHandler = try! PacketProtectorHandler(initialDCID: self.odcid, scid: self.scid, versions: [.version1], perspective: .client, remoteAddress: SocketAddress(ipAddress: "127.0.0.1", port: 1))
        XCTAssertNoThrow(try self.channel.pipeline.addHandler(self.packetProtectorHandler).wait())
    }

    override func tearDown() {
        if let channel = self.channel {
            XCTAssertNoThrow(try channel.finish(acceptAlreadyClosed: true))
            self.channel = nil
        }
        self.packetProtectorHandler = nil
    }

    /// Buffer / Read / Buffer / Read / Buffer / Read
    func testProcessInboundDatagrams2() throws {
        // Write the first datagram into the PacketProtectorHandler
        XCTAssertNoThrow(try self.channel.writeInbound(self.firstDatagram))

        // Ensure the initial packet was decrypted and is available
        let initialPacket = try? self.channel.readInbound(as: InitialPacket.self)
        XCTAssertNotNil(initialPacket)
        //print(initialPacket!.payload.hexString)

        // This shouldn't work!
        XCTAssertNil(try? self.channel.readInbound(as: HandshakePacket.self))

        // Allow Handshake Buffer Flushing
        self.packetProtectorHandler.allowHandshakeFlush()

        // Inject the Handshake Key secret
        XCTAssertNoThrow(try self.packetProtectorHandler.installHandshakeKeys(secret: Array(hexString: self.SERVER_HANDSHAKE_SECRET), for: .server, cipherSuite: .AESGCM128_SHA256))

        // At this point we should now be able to read the buffered handshake packet
        let firstHandshakePacket = try? self.channel.readInbound(as: HandshakePacket.self)
        XCTAssertNotNil(firstHandshakePacket)
        //print(firstHandshakePacket!.payload.hexString)

        XCTAssertNil(try? self.channel.readInbound(as: HandshakePacket.self))

        XCTAssertEqual(self.packetProtectorHandler.encryptedHandshakeBuffer.readableBytes, 0)

        // Write the second datagram into the PacketProtectorHandler
        XCTAssertNoThrow(try self.channel.writeInbound(self.secondDatagram))

        // Ensure the second Handshake packet was decrypted and is available
        let secondHandshakePacket = try? self.channel.readInbound(as: HandshakePacket.self)
        XCTAssertNotNil(secondHandshakePacket)

        XCTAssertNil(try? self.channel.readInbound(as: HandshakePacket.self))

        XCTAssertEqual(self.packetProtectorHandler.encryptedHandshakeBuffer.readableBytes, 0)

        // Write the third datagram into the PacketProtectorHandler
        XCTAssertNoThrow(try self.channel.writeInbound(self.thirdDatagram))

        // Ensure the third Handshake packet was decrypted and is available
        let thirdHandshakePacket = try? self.channel.readInbound(as: HandshakePacket.self)
        XCTAssertNotNil(thirdHandshakePacket)

        XCTAssertNil(try? self.channel.readInbound(as: HandshakePacket.self))
        XCTAssertNil(try? self.channel.readInbound(as: ShortPacket.self))

        XCTAssertEqual(self.packetProtectorHandler.encryptedHandshakeBuffer.readableBytes, 0)
        XCTAssertGreaterThan(self.packetProtectorHandler.encryptedTrafficBuffer.readableBytes, 0)

        // Allow Traffic Buffer Flushing
        self.packetProtectorHandler.allowTrafficFlush()

        // Inject the Handshake Key secret
        XCTAssertNoThrow(try self.packetProtectorHandler.installTrafficKeys(secret: Array(hexString: self.SERVER_TRAFFIC_SECRET), for: .server, cipherSuite: .AESGCM128_SHA256))

        // Ensure the first Traffic packet was decrypted and is available
        let firstTrafficPacket = try? self.channel.readInbound(as: ShortPacket.self)
        XCTAssertNotNil(firstTrafficPacket)

        XCTAssertNil(try? self.channel.readInbound(as: InitialPacket.self))
        XCTAssertNil(try? self.channel.readInbound(as: HandshakePacket.self))
        XCTAssertNil(try? self.channel.readInbound(as: ShortPacket.self))
        XCTAssertEqual(self.packetProtectorHandler.encryptedTrafficBuffer.readableBytes, 0)
    }

    func testProcessInboundDatagramsBurst() throws {
        // Write  first datagram into the PacketProtectorHandler
        XCTAssertNoThrow(try self.channel.writeInbound(self.firstDatagram))
        XCTAssertNoThrow(try self.channel.writeInbound(self.secondDatagram))

        // Ensure the initial packet was decrypted and is available
        let initialPacket = try? self.channel.readInbound(as: InitialPacket.self)
        XCTAssertNotNil(initialPacket)
        //print(initialPacket!.payload.hexString)

        // This shouldn't work!
        XCTAssertNil(try? self.channel.readInbound(as: HandshakePacket.self))

        // Allow Handshake Buffer Flushing
        self.packetProtectorHandler.allowHandshakeFlush()

        // Inject the Handshake Key secret
        XCTAssertNoThrow(try self.packetProtectorHandler.installHandshakeKeys(secret: Array(hexString: self.SERVER_HANDSHAKE_SECRET), for: .server, cipherSuite: .AESGCM128_SHA256))

        // At this point we should now be able to read the buffered handshake packets
        let firstHandshakePacket = try? self.channel.readInbound(as: HandshakePacket.self)
        XCTAssertNotNil(firstHandshakePacket)

        // Ensure the second Handshake packet was decrypted and is available
        let secondHandshakePacket = try? self.channel.readInbound(as: HandshakePacket.self)
        XCTAssertNotNil(secondHandshakePacket)

        XCTAssertNil(try? self.channel.readInbound(as: HandshakePacket.self))

        XCTAssertEqual(self.packetProtectorHandler.encryptedHandshakeBuffer.readableBytes, 0)

        // Write the third datagram into the PacketProtectorHandler
        XCTAssertNoThrow(try self.channel.writeInbound(self.thirdDatagram))

        // Ensure the third Handshake packet was decrypted and is available
        let thirdHandshakePacket = try? self.channel.readInbound(as: HandshakePacket.self)
        XCTAssertNotNil(thirdHandshakePacket)

        XCTAssertNil(try? self.channel.readInbound(as: HandshakePacket.self))
        XCTAssertNil(try? self.channel.readInbound(as: ShortPacket.self))

        XCTAssertEqual(self.packetProtectorHandler.encryptedHandshakeBuffer.readableBytes, 0)
        XCTAssertGreaterThan(self.packetProtectorHandler.encryptedTrafficBuffer.readableBytes, 0)

        // Allow Traffic Buffer Flushing
        self.packetProtectorHandler.allowTrafficFlush()

        // Inject the Handshake Key secret
        XCTAssertNoThrow(try self.packetProtectorHandler.installTrafficKeys(secret: Array(hexString: self.SERVER_TRAFFIC_SECRET), for: .server, cipherSuite: .AESGCM128_SHA256))

        // Ensure the first Traffic packet was decrypted and is available
        let firstTrafficPacket = try? self.channel.readInbound(as: ShortPacket.self)
        XCTAssertNotNil(firstTrafficPacket)

        XCTAssertNil(try? self.channel.readInbound(as: InitialPacket.self))
        XCTAssertNil(try? self.channel.readInbound(as: HandshakePacket.self))
        XCTAssertNil(try? self.channel.readInbound(as: ShortPacket.self))
        XCTAssertEqual(self.packetProtectorHandler.encryptedTrafficBuffer.readableBytes, 0)
    }

    // This test ensures the encrypted packets are parsed and buffered correctly
    func testProcessInboundDatagramsAllAtOnce() throws {
        // Write all three datagrams into the PacketProtectorHandler
        XCTAssertNoThrow(try self.channel.writeInbound(self.firstDatagram))
        XCTAssertNoThrow(try self.channel.writeInbound(self.secondDatagram))
        XCTAssertNoThrow(try self.channel.writeInbound(self.thirdDatagram))

        // Ensure the initial packet was decrypted and is available
        let initialPacket = try? self.channel.readInbound(as: InitialPacket.self)
        XCTAssertNotNil(initialPacket)

        // This shouldn't work!
        XCTAssertNil(try? self.channel.readInbound(as: HandshakePacket.self))

        // Allow Handshake Buffer Flushing
        self.packetProtectorHandler.allowHandshakeFlush()

        // Inject the Handshake Key secret
        XCTAssertNoThrow(try self.packetProtectorHandler.installHandshakeKeys(secret: Array(hexString: self.SERVER_HANDSHAKE_SECRET), for: .server, cipherSuite: .AESGCM128_SHA256))

        // At this point we should now be able to read the buffered handshake packets
        let firstHandshakePacket = try? self.channel.readInbound(as: HandshakePacket.self)
        XCTAssertNotNil(firstHandshakePacket)

        // Ensure the second Handshake packet was decrypted and is available
        let secondHandshakePacket = try? self.channel.readInbound(as: HandshakePacket.self)
        XCTAssertNotNil(secondHandshakePacket)

        // Ensure the third Handshake packet was decrypted and is available
        let thirdHandshakePacket = try? self.channel.readInbound(as: HandshakePacket.self)
        XCTAssertNotNil(thirdHandshakePacket)

        // This shouldn't work!
        XCTAssertNil(try? self.channel.readInbound(as: HandshakePacket.self))
        XCTAssertEqual(self.packetProtectorHandler.encryptedHandshakeBuffer.readableBytes, 0)

        // This shouldn't work!
        XCTAssertNil(try? self.channel.readInbound(as: ShortPacket.self))
        XCTAssertGreaterThan(self.packetProtectorHandler.encryptedTrafficBuffer.readableBytes, 0)

        // Allow Traffic Buffer Flushing
        self.packetProtectorHandler.allowTrafficFlush()

        // Inject the Traffic Key secret
        XCTAssertNoThrow(try self.packetProtectorHandler.installTrafficKeys(secret: Array(hexString: self.SERVER_TRAFFIC_SECRET), for: .server, cipherSuite: .AESGCM128_SHA256))

        // Ensure the first Traffic packet was decrypted and is available
        let firstTrafficPacket = try? self.channel.readInbound(as: ShortPacket.self)
        XCTAssertNotNil(firstTrafficPacket)

        XCTAssertNil(try? self.channel.readInbound(as: InitialPacket.self))
        XCTAssertNil(try? self.channel.readInbound(as: HandshakePacket.self))
        XCTAssertNil(try? self.channel.readInbound(as: ShortPacket.self))
        XCTAssertEqual(self.packetProtectorHandler.encryptedTrafficBuffer.readableBytes, 0)
    }
}
