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

import NIOCore
import XCTest
@testable import Quic

final class ByteBufferTests: XCTestCase {

    func testGetConnectionID() throws {
        let bb = try ByteBuffer(hexString: "088394c8f03e515708")
        XCTAssertEqual(bb.getConnectionID(at: 0)?.rawValue, try Array(hexString: "8394c8f03e515708"))
        XCTAssertEqual(bb.readerIndex, 0)
        XCTAssertEqual(bb.readableBytes, 9)
    }

    func testGetConnectionID_InvalidVarIntLengthPrefix() throws {
        let bb = try ByteBuffer(hexString: "088394c8f03e515708")
        XCTAssertNil(bb.getConnectionID(at: 1))
        XCTAssertEqual(bb.readerIndex, 0)
        XCTAssertEqual(bb.readableBytes, 9)
    }

    func testGetConnectionID_NotEnoughBytes() throws {
        let bb = try ByteBuffer(hexString: "088394c8f03e5157")
        XCTAssertNil(bb.getConnectionID(at: 0))
        XCTAssertEqual(bb.readerIndex, 0)
        XCTAssertEqual(bb.readableBytes, 8)
    }

    func testReadConnectionID() throws {
        var bb = try ByteBuffer(hexString: "088394c8f03e515708")
        XCTAssertEqual(bb.readConnectionID()?.rawValue, try Array(hexString: "8394c8f03e515708"))
        // Ensure the reader consumed the data
        XCTAssertEqual(bb.readerIndex, 9)
        XCTAssertEqual(bb.readableBytes, 0)
    }

    /// We treat 0 as an Invlid VarInt (not sure if this is accurate though)
//    func testReadConnectionID_InvalidVarIntLengthPrefix() throws {
//        var bb = try ByteBuffer(hexString: "008394c8f03e515708")
//        XCTAssertNil(bb.readConnectionID())
//        // Ensure the reader was rewound
//        XCTAssertEqual(bb.readerIndex, 0)
//        XCTAssertEqual(bb.readableBytes, 9)
//    }

    func testReadConnectionID_NotEnoughBytes() throws {
        var bb = try ByteBuffer(hexString: "088394c8f03e5157")
        XCTAssertNil(bb.readConnectionID())
        // Ensure the reader was rewound
        XCTAssertEqual(bb.readerIndex, 0)
        XCTAssertEqual(bb.readableBytes, 8)
    }

    func testHeaderByteInspector() throws {
        // Unprotected Header Byte
        HeaderByteInspector(UInt8(0xc3)).inspect()

        // Protected Header Byte
        HeaderByteInspector(UInt8(0xc8)).inspect()
    }

    func testPingSerialization() throws {
        var buffer = try ByteBuffer(hexString: "01")

        // Consume the Ping Frame
        guard let pingFrame = buffer.readPingFrame() else { return XCTFail("Failed to read Ping Frame") }

        // Make sure the readable portion of the buffer is empty
        XCTAssertEqual(buffer.readableBytes, 0)

        // Serialize the ping frame back into the buffer
        pingFrame.encode(into: &buffer)

        // Assert the buffer contains a single Ping Frame
        XCTAssertEqual(buffer.readableBytesView.hexString, "01")
        XCTAssertEqual(buffer.readableBytes, 1)
    }

    func testACKSerialization() throws {
        let hexString = "02000c0000"
        var buffer = try ByteBuffer(hexString: hexString)

        // Consume the ACK Frame
        guard let ack = buffer.readACKFrame() else { return XCTFail("Failed to read ACK Frame") }

        // Make sure the readable portion of the buffer is empty
        XCTAssertEqual(buffer.readableBytes, 0)

        // Serialize the ACK frame back into the buffer
        ack.encode(into: &buffer)

        // Assert the buffer contains the original data
        XCTAssertEqual(buffer.readableBytesView.hexString, hexString)

        buffer.moveReaderIndex(forwardBy: buffer.readableBytes)
        buffer.discardReadBytes()

        let ack2 = Frames.ACK(largestAcknowledged: VarInt(integerLiteral: 3), delay: VarInt(integerLiteral: 12), firstAckRange: VarInt(integerLiteral: 0), ranges: [], ecnCounts: nil)
        ack2.encode(into: &buffer)

        print(buffer.readableBytesView.hexString)
    }

    func testConsumeACKPaddingCryptoFrames() throws {
        var buffer = try ByteBuffer(hexString: "020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600405a020000560303495dbf08f721ca106cab5224bc3c44c4f4e25856c9fb84871fb70ea8061b52c600130300002e002b0002030400330024001d0020ba8103f635c4a3c8287421e2a1674409e3d85fb023f7644491e23aa8afdf0c38")

        guard let ack = buffer.readACKFrame() else { return XCTFail("Failed to consume ACK Frame") }
        print(buffer.readableBytesView.hexString)
        let padding = buffer.readPaddingFrame()
        print(buffer.readableBytesView.hexString)
        guard let crypto = buffer.readQuicCryptoFrame() else { return XCTFail("Failed to consume Crypto Frame") }
        print(buffer.readableBytesView.hexString)

        print(ack)
        print("Padding Count: \(padding)")
        print(crypto)
    }

    func testTemp() throws {
        let ackHandler = ACKHandler(epoch: .Initial)

        let pn0 = ackHandler.nextPacketNumber()
        XCTAssertEqual(pn0, 0)

        let bytes0 = pn0.bytes(minBytes: 4, bigEndian: true)
        XCTAssertEqual(bytes0, [0x00, 0x00, 0x00, 0x00])

        let pn1 = ackHandler.nextPacketNumber()
        XCTAssertEqual(pn1, 1)

        let bytes1 = pn1.bytes(minBytes: 4, bigEndian: true)
        XCTAssertEqual(bytes1, [0x00, 0x00, 0x00, 0x01])

        let timestamp1 = DispatchTime.now().uptimeNanoseconds
        print(timestamp1)
        for i in 0...100 { i * 2 }
        let timestamp2 = DispatchTime.now().uptimeNanoseconds
        print(timestamp2)

        let diff = timestamp2 - timestamp1
        print("Diff: \(diff)ns")
        print("Diff: \(diff / 1000)us")
    }

    func testConsumeClientBidiStream() throws {
        let hexString = "080048656c6c6f2073776966742d71756963"
        var buffer = try ByteBuffer(hexString: hexString)

        let streamFrame = buffer.readStreamFrame()
        XCTAssertEqual(buffer.readableBytes, 0)
        XCTAssertEqual(streamFrame?.streamType, .clientBidi)
        XCTAssertEqual(streamFrame?.type, 0x08)
        XCTAssertEqual(streamFrame?.fin, false)
        XCTAssertEqual(streamFrame?.streamID.rawValue, 0)
        XCTAssertEqual(Array(streamFrame!.data.readableBytesView), Array("Hello swift-quic".utf8))

        streamFrame?.encode(into: &buffer)

        XCTAssertEqual(buffer.readableBytesView.hexString, hexString)
    }

    func testConsumeClientUniStream() throws {
        let hexString = "080248656c6c6f2073776966742d71756963"
        var buffer = try ByteBuffer(hexString: hexString)

        let streamFrame = buffer.readStreamFrame()
        XCTAssertEqual(buffer.readableBytes, 0)
        XCTAssertEqual(streamFrame?.streamType, .clientUni)
        XCTAssertEqual(streamFrame?.type, 0x08)
        XCTAssertEqual(streamFrame?.fin, false)
        XCTAssertEqual(streamFrame?.streamID.rawValue, 2)
        XCTAssertEqual(Array(streamFrame!.data.readableBytesView), Array("Hello swift-quic".utf8))

        streamFrame?.encode(into: &buffer)

        XCTAssertEqual(buffer.readableBytesView.hexString, hexString)
    }

    func testConsumeServerBidiStream() throws {
        let hexString = "080148656c6c6f2073776966742d71756963"
        var buffer = try ByteBuffer(hexString: hexString)

        let streamFrame = buffer.readStreamFrame()
        XCTAssertEqual(buffer.readableBytes, 0)
        XCTAssertEqual(streamFrame?.streamType, .serverBidi)
        XCTAssertEqual(streamFrame?.type, 0x08)
        XCTAssertEqual(streamFrame?.fin, false)
        XCTAssertEqual(streamFrame?.streamID.rawValue, 1)
        XCTAssertEqual(Array(streamFrame!.data.readableBytesView), Array("Hello swift-quic".utf8))

        streamFrame?.encode(into: &buffer)

        XCTAssertEqual(buffer.readableBytesView.hexString, hexString)
    }

    func testConsumeServerUniStream() throws {
        let hexString = "080348656c6c6f2073776966742d71756963"
        var buffer = try ByteBuffer(hexString: hexString)

        let streamFrame = buffer.readStreamFrame()
        XCTAssertEqual(buffer.readableBytes, 0)
        XCTAssertEqual(streamFrame?.streamType, .serverUni)
        XCTAssertEqual(streamFrame?.type, 0x08)
        XCTAssertEqual(streamFrame?.fin, false)
        XCTAssertEqual(streamFrame?.streamID.rawValue, 3)
        XCTAssertEqual(Array(streamFrame!.data.readableBytesView), Array("Hello swift-quic".utf8))

        streamFrame?.encode(into: &buffer)

        XCTAssertEqual(buffer.readableBytesView.hexString, hexString)
    }

    func testConsumeClientBidiLengthStream() throws {
        let message = "Hello swift-quic"
        let streamFrame = Frames.Stream(
            streamID: StreamID(rawValue: VarInt(integerLiteral: 0)),
            offset: nil,
            length: VarInt(integerLiteral: UInt64(message.count)),
            fin: true,
            data: ByteBuffer(string: message)
        )

        var buffer = ByteBuffer()
        streamFrame.encode(into: &buffer)

        XCTAssertEqual(buffer.readableBytesView.hexString, "0b001048656c6c6f2073776966742d71756963")

        let frame = buffer.readStreamFrame()
        XCTAssertEqual(buffer.readableBytes, 0)
        XCTAssertEqual(frame?.type, 0x0b)
        XCTAssertEqual(frame?.streamID.rawValue, 0)
        XCTAssertEqual(frame?.streamType, .clientBidi)
        XCTAssertNotNil(frame?.length)
        XCTAssertNil(frame?.offset)
        XCTAssertEqual(frame?.fin, true)
        XCTAssertEqual(Array(frame!.data.readableBytesView), Array(message.utf8))
    }

    func testConsumeClientBidiOffsetAndLengthStream() throws {
        let message = "Hello swift-quic"
        let streamFrame = Frames.Stream(
            streamID: StreamID(rawValue: VarInt(integerLiteral: 0)),
            offset: VarInt(integerLiteral: 0),
            length: VarInt(integerLiteral: UInt64(message.count)),
            fin: true,
            data: ByteBuffer(string: message)
        )

        var buffer = ByteBuffer()
        streamFrame.encode(into: &buffer)

        XCTAssertEqual(buffer.readableBytesView.hexString, "0f00001048656c6c6f2073776966742d71756963")

        let frame = buffer.readStreamFrame()
        XCTAssertEqual(buffer.readableBytes, 0)
        XCTAssertEqual(frame?.type, 0x0f)
        XCTAssertEqual(frame?.streamID.rawValue, 0)
        XCTAssertEqual(frame?.streamType, .clientBidi)
        XCTAssertNotNil(frame?.length)
        XCTAssertNotNil(frame?.offset)
        XCTAssertEqual(frame?.fin, true)
        XCTAssertEqual(Array(frame!.data.readableBytesView), Array(message.utf8))
    }

    func testReadACKandCryptoFrame() throws {
        let hexString = "02000000000600405a020000560303a335159bdb3fd94df015509ca44275695127bccee80adf405eb0406d30e2da3e00130300002e002b0002030400330024001d002051dd955520d0b8f347478cbd4c36774a9f480095e6adcef6bd7720e4e940e304"
        var buffer = try ByteBuffer(hexString: hexString)

        guard let ack = buffer.readACKFrame() else { return XCTFail("Failed to read ACK Frame") }
        guard let crypto = buffer.readCryptoFrame() else { return XCTFail("Failed to read Crypto Frame") }

        XCTAssertEqual(buffer.readableBytes, 0)

        ack.encode(into: &buffer)
        crypto.encode(into: &buffer)

        XCTAssertEqual(buffer.readableBytesView.hexString, hexString)
    }

    func testReadNewConnectionIDs() throws {
        let hexString = "18050004ab960a7330ec1904e160bade6cdb263575a0f87218040004004bb28b81e6ceca4825814109e2117d9ae8ad9f18030004b97a7f2ab493877f6c9ff5d7e31d895f91bbc09a180200044c828a40b0bf002a18e2a784cc717284cc0b222f18010004c82f61762f4b2b225316f31040486c08edeb0cca"
        var buffer = try! ByteBuffer(hexString: hexString)

        let ncid5 = Frames.NewConnectionID(sequenceNumber: VarInt(integerLiteral: 5), retirePriorTo: VarInt(integerLiteral: 0), connectionID: ConnectionID(arrayLiteral: 0xab, 0x96, 0x0a, 0x73), statelessResetToken: [0x30, 0xec, 0x19, 0x04, 0xe1, 0x60, 0xba, 0xde, 0x6c, 0xdb, 0x26, 0x35, 0x75, 0xa0, 0xf8, 0x72])
        let ncid4 = Frames.NewConnectionID(sequenceNumber: VarInt(integerLiteral: 4), retirePriorTo: VarInt(integerLiteral: 0), connectionID: ConnectionID(arrayLiteral: 0x00, 0x4b, 0xb2, 0x8b), statelessResetToken: [0x81, 0xe6, 0xce, 0xca, 0x48, 0x25, 0x81, 0x41, 0x09, 0xe2, 0x11, 0x7d, 0x9a, 0xe8, 0xad, 0x9f])
        let ncid3 = Frames.NewConnectionID(sequenceNumber: VarInt(integerLiteral: 3), retirePriorTo: VarInt(integerLiteral: 0), connectionID: ConnectionID(arrayLiteral: 0xb9, 0x7a, 0x7f, 0x2a), statelessResetToken: [0xb4, 0x93, 0x87, 0x7f, 0x6c, 0x9f, 0xf5, 0xd7, 0xe3, 0x1d, 0x89, 0x5f, 0x91, 0xbb, 0xc0, 0x9a])
        let ncid2 = Frames.NewConnectionID(sequenceNumber: VarInt(integerLiteral: 2), retirePriorTo: VarInt(integerLiteral: 0), connectionID: ConnectionID(arrayLiteral: 0x4c, 0x82, 0x8a, 0x40), statelessResetToken: [0xb0, 0xbf, 0x00, 0x2a, 0x18, 0xe2, 0xa7, 0x84, 0xcc, 0x71, 0x72, 0x84, 0xcc, 0x0b, 0x22, 0x2f])
        let ncid1 = Frames.NewConnectionID(sequenceNumber: VarInt(integerLiteral: 1), retirePriorTo: VarInt(integerLiteral: 0), connectionID: ConnectionID(arrayLiteral: 0xc8, 0x2f, 0x61, 0x76), statelessResetToken: [0x2f, 0x4b, 0x2b, 0x22, 0x53, 0x16, 0xf3, 0x10, 0x40, 0x48, 0x6c, 0x08, 0xed, 0xeb, 0x0c, 0xca])

        guard let newConnID5 = buffer.readNewConnectionIDFrame() else { return XCTFail("Failed to read NewConnectionID Frame") }
        XCTAssertEqual(newConnID5, ncid5)

        guard let newConnID4 = buffer.readNewConnectionIDFrame() else { return XCTFail("Failed to read NewConnectionID Frame") }
        XCTAssertEqual(newConnID4, ncid4)

        guard let newConnID3 = buffer.readNewConnectionIDFrame() else { return XCTFail("Failed to read NewConnectionID Frame") }
        XCTAssertEqual(newConnID3, ncid3)

        guard let newConnID2 = buffer.readNewConnectionIDFrame() else { return XCTFail("Failed to read NewConnectionID Frame") }
        XCTAssertEqual(newConnID2, ncid2)

        guard let newConnID1 = buffer.readNewConnectionIDFrame() else { return XCTFail("Failed to read NewConnectionID Frame") }
        XCTAssertEqual(newConnID1, ncid1)

        XCTAssertEqual(buffer.readableBytes, 0)

        // Serialize the NewConnectionID frames back into the ByteBuffer
        newConnID5.encode(into: &buffer)
        newConnID4.encode(into: &buffer)
        newConnID3.encode(into: &buffer)
        newConnID2.encode(into: &buffer)
        newConnID1.encode(into: &buffer)

        //ncid5.encode(into: &buffer)
        //ncid4.encode(into: &buffer)
        //ncid3.encode(into: &buffer)
        //ncid2.encode(into: &buffer)
        //ncid1.encode(into: &buffer)

        // Assert that the encoded data matches the original
        XCTAssertEqual(buffer.readableBytesView.hexString, hexString)
    }

    func testNewTokenFrameSerialization() throws {
        let hexString = "07404a892cd16f569478fd3944300e29fbcbf3ec0acbc3c174c5af41a23a3bd3870c1a06aeed9aa56613dae55e612bd98edb0d99eb3ed23e9384b145b1f11ec29042646f69c9b60eace710d1f3"
        var buffer = try! ByteBuffer(hexString: hexString)

        // Consume the NewToken frame
        guard let newTokenFrame = buffer.readNewTokenFrame() else { return XCTFail("Failed to read NewToken Frame") }

        // Ensure the readable portion of the buffer is empty
        XCTAssertEqual(buffer.readableBytes, 0)

        // Serialize the NewToken frame back into the buffer
        newTokenFrame.encode(into: &buffer)

        // Assert that the encoded data matchces the original
        XCTAssertEqual(buffer.readableBytesView.hexString, hexString)
    }

    /// This test is the exact same as `testInitialPacketEncoding_Appendix_A_1` except it uses the above helper functions
    func testInitialPacketDecoding_Appendix_A_1_Short_ByteBuffer() throws {
        let expectedPublicFlag = "c3"
        let expectedVersion = "00000001"
        let expectedDcidLength = "08"
        let expectedDcid = "8394c8f03e515708"
        let expectedScidLength = "00"
        let expectedTokenLength = "00"
        let expectedPacketLength = "449e" //1182 in decimal (protected payload byte count (1178) + packet number byte count (4) = 1182)
        let expectedPacketNumber = "00000002" // 4 bytes

        let expectedSample = "d1b1c98dd7689fb8ec11d242b123dc9b"
        let expectedClientKey = "1f369613dd76d5467730efcbe3b1a22d"
        let expectedClientIV = "fa044b2f42a3fd3b46fb255c"
        let expectedClientHP = "9f50449e04a0e810283a1e9933adedd2"

        let initialSalt = "38762cf7f55934b34d179ae6a4c80cadccbb7f0a"
        let clientIn = "00200f746c73313320636c69656e7420696e00"

        let expectedUnprotectedHeader = "c300000001088394c8f03e5157080000449e00000002"
        let expectedNonce = "fa044b2f42a3fd3b46fb255e"

        var buffer = try ByteBuffer(hexString: "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f3991c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df621230c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c2084dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f89937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c7468449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663ac69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe5896425c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ffef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009ddc324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77fcb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450efc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03adea2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e72404790a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f440591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca06948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f0940054da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd46840647e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241e221af44860018ab0856972e194cd934")

        let expectedPayload = "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578616d706c652e636f6dff01000100000a00080006001d0017001800100007000504616c706e000500050100000000003300260024001d00209370b2c9caa47fbabaf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b0003020304000d0010000e0403050306030203080408050806002d00020101001c00024001003900320408ffffffffffffffff05048000ffff07048000ffff0801100104800075300901100f088394c8f03e51570806048000ffff"

        guard let headerByte = buffer.getBytes(at: 0, length: 1)?.first else { return XCTFail("No HeaderByte") }
        guard let packetType = PacketType(headerByte) else { return XCTFail("Invalid HeaderByte") }
        guard packetType.isLongHeader else { return XCTFail("Invalid packet type") }
        let info = try buffer.getLongHeaderPacketNumberOffset(at: 0, isInitial: packetType == .Initial)
        XCTAssertEqual(info.packetNumberOffset, 18)
        XCTAssertEqual(info.packetLength, 1182)
        XCTAssertEqual(Int(info.packetLength) + info.packetNumberOffset, buffer.readableBytes)

        // At this point we know the protected header bytes, and the encrypted payload bytes
        guard let version = buffer.getVersion(at: 1), isSupported(version: version) else { return XCTFail("Invalid Version") }
        guard let dcid = buffer.getConnectionID(at: 5) else { return XCTFail("Invalid DCID") }
        let packetProtector = try version.newInitialAEAD(connectionID: dcid, perspective: .server)

        // Unprotect Header
        let unprotectedHeaderLength = try buffer.removeLongHeaderProtection(at: 0, packetNumberOffset: info.packetNumberOffset, sampleSize: 16, using: packetProtector.opener!)
        XCTAssertEqual(buffer.viewBytes(at: 0, length: unprotectedHeaderLength)?.hexString, expectedUnprotectedHeader)
        let packetNumber = buffer.getBytes(at: info.packetNumberOffset, length: unprotectedHeaderLength - info.packetNumberOffset)
        XCTAssertEqual(packetNumber, [0x00, 0x00, 0x00, 0x02])

        // Decrypt Payload
        try buffer.decryptBytes(at: unprotectedHeaderLength, packetLength: Int(info.packetLength), headerOffset: 0, packetNumber: packetNumber!, using: packetProtector.opener!, paddingRemovalStrategy: .dropTrailingZeros)
        print(buffer.readableBytesView.hexString)

        XCTAssertEqual(buffer.readableBytesView.hexString, expectedUnprotectedHeader + expectedPayload)
        HeaderByteInspector(buffer.getBytes(at: buffer.readerIndex, length: 1)!.first!).inspect()
    }

    func testInitialPacketDecoding_GoQuic() throws {
        // This is an IntialPacket sent from a Go QUIC client
        // DCID = "26cdadb496c6228a9a6c4e983a9a758ae45833" | SCID = "0e01ef80"
        var buffer = try ByteBuffer(hexString: "c9ff00001d1326cdadb496c6228a9a6c4e983a9a758ae45833040e01ef800044c347cd4d7a938b152379fd2f4028e348960d877cdf2508b3c1308d8491ae1d1957bc5889a9258d91f76d410724d503817785178b1a18163b6859ea4984e0a217137211a943f50583621ee70cf4ea0f7d1021b4defe83202f56116b24e4ebfe8e7c6ea8debcd48dbd00f2bf393d670ef82feab77b0faeaa367a86a2ec33a237f9cbb921df3edcfd27f8be44a3e58d965725e4645f984e6d527c29ff2e121357c8a5cbf0f270978d5b2e93a4d452c277e49ec6acfc1cabe7151e9bd9900f2ba41b4b4302df55e4857682c16dcb4673dabf98f09e072fa05644ff807fc6bacb4ead23b7ecffca28d72e30767bf66f8bcf7317bc28924f360b946cc29e7513e8ab57bfbfb92b0c71a5bb8f0f12815ec8d49ecd93b30861e5cb81ed38f810f8109ba08d5e0fce77d53df35c4b330962ab420e3ac803ea00e3d3684c404a0efe081560dc304818f50e0bd133a57b429dc3ca0070c5f5642070a84b7567fd7fc750cfeabda98805939ce396ce5e01d90e24575ee0b81ca5ff16b011b3b7bade96b70d1f4a112f0439c3e38a616413aa4093c837b81aaba2047f0934b553cb8eb3507d55dc1bc78bf084c992c2fbd4aad58ddf258994eddeac0aa2d912cace30e49a36f169696697b429a999b9cc90f1e5a5b5f53aac8e3cea139ea48ece2b44e5b1c499717e4866009f89c8d206500d327e405edf83480b58a12d8b0655eb8a8969c9c0bc196f330d1156ebc96321b55aca1fb04b6c0e2d9f91670dd991974573f73e47c956f9fa44c1c97eaec639a99ede8a7d35f91c70d8b2eec28938aefca7556e7dd2c320779ba1f63dc8534bbf7f8ee06a5b88483d7ac8e1ae7c41bb04e9484d684445a949470113ee80652847e25cc268937824755599eea0a91bc05f9dd2aba50e9cb7840328028ca24c7602e57034935c9e14045bd072463d83f0e41d64288c97df23522c634f50fd09e14ced71da6b0d0b9f5f1f3ae9e8e31595dfeecf6b697fe93de155acf706a81e5033896a8fc67af61399c1d9d0644ddcb8593678a814c36d5c55ba4769c41999f4dab6c63906a54608279db7197c26fde1911c4285d9608df0fe3f9388d2804c9d2c53322aa83ae028b8f0a0d80b86bf52b548830d4d20af101da2dbccc981d778cc3190457f99bde6a623acdfade3ac7ee8f04892d5a24e05c60abdf128c022d765987001363934f9850633c2f039b51bbbee5e58ed18d811d91f43bb11d2df788c8337f29cd00705ee1a7310bf05b288c282a8b9c3ecd8aff10da7adf729781fe0afb34be731479bc4a06a2b513072e57b4c9260fecd458445cd48d314db3febe1babd1f17186a743f8d1e902d4e9ff794174501c25c2668cc61fe736b9a1f2fb3b48e7749f977f7b36820cb81f62d975ae5929613e536ca14f6388e04b42f92b0cc870e3f1a65cf7c65303dc8504309bfb07be06668cefd1e736dc87f363c8623df6598d9e0262b2a29d85b7daeaa807c18620c3afb58e35e14c3f1e56e88e53b515a568015ada1dcd6bfeff2cb5152ff4ef359254f0410448b703f0875648345bf72050ffb9844135bfa58a2b5f67c4946fa5bacaeabdf1838876f5ef80ee44f216a8b933a0e31e0a31db4065f8982e6bcf36f978bfafdf31b73f51be945d1ac209c98f0e7944576fcb3c77aa7816107b673bf04783628f0b3fda0bd1a9a9529bca3de9887395d88a9fa0a5e091f06458dbd4be21dd31d16")

        let expectedUnprotectedHeader = "c1ff00001d1326cdadb496c6228a9a6c4e983a9a758ae45833040e01ef800044c30000"
        let expectedPayload = "060041200100011c0303a812d421316d300d97580e3570f82e50d67f6e0bbce6951650f380dd15196fe8000026c02bc02fc02cc030cca9cca8c009c013c00ac014009c009d002f0035c012000a130113021303010000cd000500050100000000000a000a0008001d001700180019000b00020100000d001a0018080404030807080508060401050106010503060302010203ff01000100001000090007066c696270327000120000002b0003020304003300260024001d0020713301fc1654935c5c180c3da916a382ed228628bd1d22c0b5132c60d69ad145ffa5004740d50d2b808197835dab0f56d2af7f0a0504800800000604800800000704800800000404800c000008024100090100010480007530030245ac0b011a0c000e01040f040e01ef80"

        guard let headerByte = buffer.getBytes(at: 0, length: 1)?.first else { return XCTFail("No HeaderByte") }
        guard let packetType = PacketType(headerByte) else { return XCTFail("Invalid HeaderByte") }
        guard packetType.isLongHeader else { return XCTFail("Invalid packet type") }
        let info = try buffer.getLongHeaderPacketNumberOffset(at: 0, isInitial: packetType == .Initial)
        XCTAssertEqual(info.packetNumberOffset, 33)
        XCTAssertEqual(info.packetLength, 1219)
        XCTAssertEqual(Int(info.packetLength) + info.packetNumberOffset, buffer.readableBytes)

        // At this point we know the protected header bytes, and the encrypted payload bytes
        guard let version = buffer.getVersion(at: 1), isSupported(version: version) else { return XCTFail("Invalid Version") }
        guard let dcid = buffer.getConnectionID(at: 5) else { return XCTFail("Invalid DCID") }
        let packetProtector = try version.newInitialAEAD(connectionID: dcid, perspective: .server)

        // Unprotect Header
        let unprotectedHeaderLength = try buffer.removeLongHeaderProtection(at: 0, packetNumberOffset: info.packetNumberOffset, sampleSize: 16, using: packetProtector.opener!)
        XCTAssertEqual(buffer.viewBytes(at: 0, length: unprotectedHeaderLength)?.hexString, expectedUnprotectedHeader)
        let packetNumber = buffer.getBytes(at: info.packetNumberOffset, length: unprotectedHeaderLength - info.packetNumberOffset)
        XCTAssertEqual(packetNumber, [0x00, 0x00])

        // Decrypt Payload
        try buffer.decryptBytes(at: unprotectedHeaderLength, packetLength: Int(info.packetLength), headerOffset: 0, packetNumber: packetNumber!, using: packetProtector.opener!, paddingRemovalStrategy: .dropLeadingZeros)
        print(buffer.readableBytesView.hexString)

        XCTAssertEqual(buffer.readableBytesView.hexString, expectedUnprotectedHeader + expectedPayload)
        HeaderByteInspector(buffer.getBytes(at: buffer.readerIndex, length: 1)!.first!).inspect()
    }

    func testInitialPacketDecoding_GoQuic_v2() throws {
        // This is an IntialPacket sent from a Go QUIC client
        var buffer = try ByteBuffer(hexString: "c8ff00001d0918af10fdfa370dd3b304d0b92e090044cd44bbbfdf74505084f6c2dcbfdb3b4862abaad58676a05b75fb205551b56c3036a5142b679f8d48a65e0c6873780284722211e89324e595bc58e7341916537eb88a6a62daf10104f8e92f1b0d7cb9183d2e58c83bd98f4c251b90adcfbc78cc2922235f44643b4f93cd5dd4336cb83993cdc59aacd422d08f89558562145eb6a802dd806679ff154332210605649211987698fe66956025ed94bdd135315b54b2523c20b603952976c54ccdd64c9773addfae17deb628ec3dbd7e19b3ebaf44e37b342b7f0ca3e598010c582e557e25d8fc1e3908d801104710b8929d7269bbfb82256841bf7089891cdc5d61f0f227dca01ab67b57c00bcb73fc62d2326585c554d40a3f2363ce8da40e5bc68e77831ee8a0ca815fc5297f64acbee4588dd16fbf7633a3eacc9a69c26dc96e7f5ae77654c6d1b83e9de3087d16257f617074c53dcb85b0eb63492a1520afa4f8f0c4078d3f674c24f393fca1602f8edef1c5feac002d221959d6bfdf1cb26791644d17bf6b5bbe846790566b883e65ffa0d0df57c0610f4f5d78367c613f9e6cf76a447917bf0a1cf07efe5beb4180ac2d316565ea2dccf4b59d880d6e09ad33f842e79f91ec61e83433f4ff75c9ecc538a3fb578366c4604e226b100f2b769f32a81f175000cc05ce28a66ecf56129710ebfae04b6bad72acfc25af43330eb54090173b7e0e2cdba3c63c11281f941e57d1c39b5b9263a783ae8128bd592e898565b89b9043a8f3dc10ca5214fafd05d854315e86d71e2374ab6cc7c6903cc9e35cd0de493a1d30d4cc3fb380cc52183a01c5281eb081aa1c9c7d48e1861ce1c62f024b6dcedcf8940c0961d605b79dd3495f8069e6b84ab7e32d7d5943ea95cd169f4df6031e93cd129a593725c5841bcc5970fa4e0ce2ad713330c6ea41aea65f25b92aad30dd5f27fa9fff8fbac82ffc3c5bdb9c20b2186869087fc1ccff04779ccde82078c5479554c054351c2fb3628585f9ab87ab94e6076fa6e10af1ae4ec009ea8a613a90378c97857594ce4612e6f07c486a0cae5799ade6d386c7831394a9da436153553764589b84f7eb6a2ab577028040be8c14afbdb441013b7335a73702c3cb508f06b0831b4708a0e2dbf329ec2970089af33928bea8b89c02b603ffccb170e823320afd30d45eeff68f93227989844795d6345465e3db35c17f096b42c68f1a187db5658fbee4fed802465d94edf2e6e1d8a9b550bfd8ffe737894bca29fee09b74e31aecda421d947997834014423754d7e839ed6fc7017fc5be68df45d08c3196173329749eab2b29197bb353a9e9ab9362d252ee4b514eb288f7467a6d7eaaab7cd449de334fbe61230d4698cdf52465fa78b2a14a647aa107aed426e131fc24d1c10a25c6f43de2abe99176b2e798785b8a98e3b8d46540041279311fb6b158fc0971e4f19200359bad597e8b7287ac44ae8a91b93885fedc430d46f6bbee672a5445863553cf55bec02e9764d46dfc558bac0802a1209018e58e3765b6cbb79f6b6ce3a75877b39407eaae6afc6d43df90787ba49595e507d005c14ac15637f2a5965b0412f2d5301d5f4f0421d311283bc04d7449b8fa59c1cb0d3df9e0f687967b0545c4e2414a186eb5f94b252bff4fbce05ae4db148b61e011132329888154c74c0ec4ed78d22aa39f74d4d793b42da8225ee12b896007c18e5c6f842c1ac46801345b74111a241a4cf14aae630cb7970b51cd")

        let expectedUnprotectedHeader = "c1ff00001d0918af10fdfa370dd3b304d0b92e090044cd0007"
        let expectedPayload = "0600411a010001160303c1a7ab52c34ba6750648ab7020ed72fe347891126d41aa527bb8cab120f47259000026c02bc02fc02cc030cca9cca8c009c013c00ac014009c009d002f0035c012000a130113021303010000c7000500050100000000000a000a0008001d001700180019000b00020100000d001a0018080404030807080508060401050106010503060302010203ff01000100001000090007066c696270327000120000002b0003020304003300260024001d0020473af2bae35114c75cdaf759e2f8ae4b25d833d7ab115b10ee33ac192b00b93effa500414bf9079472fded4dac080504800800000604800800000704800800000404800c000008024100090100010480007530030245ac0b011a0c000e01040f04d0b92e09"

        guard let headerByte = buffer.getBytes(at: 0, length: 1)?.first else { return XCTFail("No HeaderByte") }
        guard let packetType = PacketType(headerByte) else { return XCTFail("Invalid HeaderByte") }
        guard packetType.isLongHeader else { return XCTFail("Invalid packet type") }
        let info = try buffer.getLongHeaderPacketNumberOffset(at: 0, isInitial: packetType == .Initial)
        XCTAssertEqual(info.packetNumberOffset, 23)
        XCTAssertEqual(info.packetLength, 1229)
        XCTAssertEqual(Int(info.packetLength) + info.packetNumberOffset, buffer.readableBytes)

        // At this point we know the protected header bytes, and the encrypted payload bytes
        guard let version = buffer.getVersion(at: 1), isSupported(version: version) else { return XCTFail("Invalid Version") }
        guard let dcid = buffer.getConnectionID(at: 5) else { return XCTFail("Invalid DCID") }
        let packetProtector = try version.newInitialAEAD(connectionID: dcid, perspective: .server)

        // Unprotect Header
        let unprotectedHeaderLength = try buffer.removeLongHeaderProtection(at: 0, packetNumberOffset: info.packetNumberOffset, sampleSize: 16, using: packetProtector.opener!)
        XCTAssertEqual(buffer.viewBytes(at: 0, length: unprotectedHeaderLength)?.hexString, expectedUnprotectedHeader)
        let packetNumber = buffer.getBytes(at: info.packetNumberOffset, length: unprotectedHeaderLength - info.packetNumberOffset)
        XCTAssertEqual(packetNumber, [0x00, 0x07])

        // Decrypt Payload
        try buffer.decryptBytes(at: unprotectedHeaderLength, packetLength: Int(info.packetLength), headerOffset: 0, packetNumber: packetNumber!, using: packetProtector.opener!, paddingRemovalStrategy: .dropLeadingZeros)
        print(buffer.readableBytesView.hexString)

        XCTAssertEqual(buffer.readableBytesView.hexString, expectedUnprotectedHeader + expectedPayload)
        HeaderByteInspector(buffer.getBytes(at: buffer.readerIndex, length: 1)!.first!).inspect()
    }

    func testHandshakePacketDecoding_GoQuic_v1() throws {
        let dcid = try Array(hexString: "6fa8a98178f2da89")

        // This is an ServerHello sent from a Go QUIC server (contains an InitialPacket and a Handshake Packet)
        var buffer = try ByteBuffer(hexString: "ce0000000104dfd1b3b6048c9a80c100407577154862384d1435514a484cb9d736aacf9588d1c7eb61b1f0f961653a09c05cd37ddd1d83b52943b296e5bc3ea38125ed3a91bc747cab1a5d1842a6441004b9fc92b21c4a4cf0616f63aeef5dfc6dc045cd613339cf7426a967c7cb438a5cc16d9a45e0d25c187aafae4a4ea7d5475afef1f30ab6e00000000104dfd1b3b6048c9a80c1444c47542a6e411e47d1ce2a673e4d0ea3f91d5c07f003e30db525e4af18b8dd52b2a403487860a89816352497cd32b46af17be91e10d4515b5754e2d84950952548be966c8ddd0fc8fd98eb35d3afe95f74944dc26bd2d8a738a232eb629f9b637c5f7c503e924616e1c42182618780aad643213dc8f046402d7012e0780af4b426be05bcfd250ec9d499837dee36ade02802dfe05c6d9f9fd95a79525dd1b7eff90bbde1cc80d19485c3f22efbc8762f0935685a3edbe676ffa3890184f6796192d8cb0b28a247e9ec5b386b0abdd30bbcaa312ff859f06a115249cf63a09b41e47637f0f74fb737c9217c0224a796ac3d8632c51b4555c3dea14a7f9054bcfccef60270d3682711548dc7bc9e66e598a0c50b0288f2346b853eb57dc5387ca4d77a4f4288c866b59b0b0c51f0d58aec9500e22fe33dd0b5d8bdbfa8e3a36295c99371028f70561faf0c20306077c98d4d3751e4b55417f4038e0e022d2f30fb244b0c3f75d4af6b6aedfefb7cb41e23e180bb1843027e8d857fe8dd2168ec6fcce72ab3e7781dbd9c4c40514b2f5c876cda3015241edcef9e7e12f179de2d13de6b4c497df7f36216f572c9233180ea27c65f66392886e1ad2b3f18bb33a2d811d718e49eeae82c5c0b75d6d8c3623e0c2c2d6550a483a2298bbef77b0ead620da046aa362b62df539b5fbe5f0b8da72fcf26a06cd4e6bb0bde30e9d45bfd5a5bddee6160f5aecaa61b8713c42feb411a1132df5deaedf9467e00be040c2929a7275c75d7abb7937cb06505fb875b7382cd44a1025d0a8dda2715b9e1288f05b2e37132f96607957f8a0fc5fefc17eb70e37abd2f441cec09c0e8750f6729808254ac6eeb6e3de808d1ee0adf3d46b7025621f86c80da69d5bec7de06c2a93fdda7a7db1a1980257499f297b158dba2f7e2de7e7b7df0377fb8a8614b65bc4857286ad5244636acd3041ce525d87e178dd8f079c5f00b47d672c752949a41dcdbbffa9682be3a93cd650bf4594740aea5c7018e356ff9459329a0e182b12ef4c2ac1bb39bbb61381d05a6e643c99bb68db7b43d12110094b5b91abe16d3cc3ae172e2f5493041f8d43fec8ea3e56ef79343ae5f18e5601c102ab53e808871fb8aa9489a6eeee4ac7f26b465959257f9ee5debfe2799a27338ea10b990850291c38028ba78a082a891a43575f701a5dd478bef59c624819b88582c89f3c44683055ada867682351229b22ef6a0c280021440a9d1f2b4393f63015d2e6515ac7731d8800db827cb645b034bf0ff58ebda4d2aeeb4a055ca6263099d7ec196786849e25ea7905511b53bbb294a5dac5084db50d60572df5a767beee0ebb5c168cb1706c343c607dc5533bbf5a8ebc51b9bd135cb649eec7fb3e677d3051ad615cfd5abb0330f6549f9268fa304dc89e818949c536b5df11ba464845d4418352426cfddde2ddab5107ad66e80aac57cd98e43d689f3c35bb7401005becc2bd6f7179795838c915a406e848b898fa368c331c16e08622bb72f07224db886346c0bcc0490a934448c7f0e597539cceb")

        let expectedUnprotectedHeader = "c10000000104dfd1b3b6048c9a80c10040750000"
        let expectedPayload = "02000000000600405a02000056030308b9bb52fdab699405c1a0b4d07906bb78aa7a2a338b3b87d87548219c6a38ad00130100002e002b0002030400330024001d002017d3f1f8de8848dc690aae5587682bf74174997dc7e674ed3cac7009b37ca73c"

        guard let headerByte = buffer.getBytes(at: 0, length: 1)?.first else { return XCTFail("No HeaderByte") }
        guard let packetType = PacketType(headerByte) else { return XCTFail("Invalid HeaderByte") }
        guard packetType.isLongHeader else { return XCTFail("Invalid packet type") }
        let info = try buffer.getLongHeaderPacketNumberOffset(at: 0, isInitial: packetType == .Initial)
        XCTAssertEqual(info.packetNumberOffset, 18)
        XCTAssertEqual(info.packetLength, 117)

        // At this point we know the protected header bytes, and the encrypted payload bytes
        guard let version = buffer.getVersion(at: 1), isSupported(version: version) else { return XCTFail("Invalid Version") }
        XCTAssertEqual(version, .version1)
        //guard let dcid = buffer.getConnectionID(at: 5) else { return XCTFail("Invalid DCID") }
        let packetProtector = try version.newInitialAEAD(connectionID: ConnectionID(with: dcid), perspective: .client)

        // Unprotect Header
        let unprotectedHeaderLength = try buffer.removeLongHeaderProtection(at: 0, packetNumberOffset: info.packetNumberOffset, sampleSize: 16, using: packetProtector.opener!)
        XCTAssertEqual(buffer.viewBytes(at: 0, length: unprotectedHeaderLength)?.hexString, expectedUnprotectedHeader)
        let packetNumber = buffer.getBytes(at: info.packetNumberOffset, length: unprotectedHeaderLength - info.packetNumberOffset)
        XCTAssertEqual(packetNumber, [0x00, 0x00])

        // Decrypt Payload
        try buffer.decryptBytes(at: unprotectedHeaderLength, packetLength: Int(info.packetLength), headerOffset: 0, packetNumber: packetNumber!, using: packetProtector.opener!, paddingRemovalStrategy: .doNothing)
        print(buffer.viewBytes(at: buffer.readerIndex, length: 119)!.hexString)

        XCTAssertEqual(buffer.viewBytes(at: buffer.readerIndex, length: 119)!.hexString, expectedUnprotectedHeader + expectedPayload)
        HeaderByteInspector(buffer.getBytes(at: buffer.readerIndex, length: 1)!.first!).inspect()

        print("Done with ServerHello, proceeding with Handshake")
        print(buffer.readableBytesView.hexString)

        var handshakeByteBuffer = try ByteBuffer(hexString: "e00000000104dfd1b3b6048c9a80c1444c47542a6e411e47d1ce2a673e4d0ea3f91d5c07f003e30db525e4af18b8dd52b2a403487860a89816352497cd32b46af17be91e10d4515b5754e2d84950952548be966c8ddd0fc8fd98eb35d3afe95f74944dc26bd2d8a738a232eb629f9b637c5f7c503e924616e1c42182618780aad643213dc8f046402d7012e0780af4b426be05bcfd250ec9d499837dee36ade02802dfe05c6d9f9fd95a79525dd1b7eff90bbde1cc80d19485c3f22efbc8762f0935685a3edbe676ffa3890184f6796192d8cb0b28a247e9ec5b386b0abdd30bbcaa312ff859f06a115249cf63a09b41e47637f0f74fb737c9217c0224a796ac3d8632c51b4555c3dea14a7f9054bcfccef60270d3682711548dc7bc9e66e598a0c50b0288f2346b853eb57dc5387ca4d77a4f4288c866b59b0b0c51f0d58aec9500e22fe33dd0b5d8bdbfa8e3a36295c99371028f70561faf0c20306077c98d4d3751e4b55417f4038e0e022d2f30fb244b0c3f75d4af6b6aedfefb7cb41e23e180bb1843027e8d857fe8dd2168ec6fcce72ab3e7781dbd9c4c40514b2f5c876cda3015241edcef9e7e12f179de2d13de6b4c497df7f36216f572c9233180ea27c65f66392886e1ad2b3f18bb33a2d811d718e49eeae82c5c0b75d6d8c3623e0c2c2d6550a483a2298bbef77b0ead620da046aa362b62df539b5fbe5f0b8da72fcf26a06cd4e6bb0bde30e9d45bfd5a5bddee6160f5aecaa61b8713c42feb411a1132df5deaedf9467e00be040c2929a7275c75d7abb7937cb06505fb875b7382cd44a1025d0a8dda2715b9e1288f05b2e37132f96607957f8a0fc5fefc17eb70e37abd2f441cec09c0e8750f6729808254ac6eeb6e3de808d1ee0adf3d46b7025621f86c80da69d5bec7de06c2a93fdda7a7db1a1980257499f297b158dba2f7e2de7e7b7df0377fb8a8614b65bc4857286ad5244636acd3041ce525d87e178dd8f079c5f00b47d672c752949a41dcdbbffa9682be3a93cd650bf4594740aea5c7018e356ff9459329a0e182b12ef4c2ac1bb39bbb61381d05a6e643c99bb68db7b43d12110094b5b91abe16d3cc3ae172e2f5493041f8d43fec8ea3e56ef79343ae5f18e5601c102ab53e808871fb8aa9489a6eeee4ac7f26b465959257f9ee5debfe2799a27338ea10b990850291c38028ba78a082a891a43575f701a5dd478bef59c624819b88582c89f3c44683055ada867682351229b22ef6a0c280021440a9d1f2b4393f63015d2e6515ac7731d8800db827cb645b034bf0ff58ebda4d2aeeb4a055ca6263099d7ec196786849e25ea7905511b53bbb294a5dac5084db50d60572df5a767beee0ebb5c168cb1706c343c607dc5533bbf5a8ebc51b9bd135cb649eec7fb3e677d3051ad615cfd5abb0330f6549f9268fa304dc89e818949c536b5df11ba464845d4418352426cfddde2ddab5107ad66e80aac57cd98e43d689f3c35bb7401005becc2bd6f7179795838c915a406e848b898fa368c331c16e08622bb72f07224db886346c0bcc0490a934448c7f0e597539cceb")

        // Once we pass this ServerHello crypto frame into TLS we get the following secrets...
        //let clientRandom = try Array(hexString: "c9eadddc326d2557a8283675c77304fbcccadb6910a4d12a6402b325dcb2d590")

        // 🔐 Session Secret Generated! 🔐 CLIENT_HANDSHAKE_TRAFFIC_SECRET
        let clientHandshakeTrafficSecret = try Array(hexString: "ab105e2f1f22c03583f80d31403e11c191352d9684440231c2849d4b248c3e83")

        // 🔐 Session Secret Generated! 🔐 SERVER_HANDSHAKE_TRAFFIC_SECRET
        let serverHandshakeTrafficSecret = try Array(hexString: "a35b7ccf5dc8bdfc2691d7880beff7c5943f3d00df6180f95de9f8a295e41c39")

        let expectedUnprotectedHandshakeHeader = "e10000000104dfd1b3b6048c9a80c1444c0000"
        let expectedHandshakePayload = "0600443608000071006f0010000500030268330039006244580b35ece6c6b55af6f17b8fc50504800800000604800800000704800800000404800c00000802406409024064010480007530030245ac0b011a0c000210aaab7a6cb4ef124b17ca3febb59cf1f300086fa8a98178f2da890e01040f048c9a80c10b0003130000030f00030a30820306308201ee020900a7f24e0a3cdf0350300d06092a864886f70d01010b05003045310b3009060355040613025553310b300906035504080c02434131153013060355040a0c0c73776966742d6c69627032703112301006035504030c096c6f63616c686f7374301e170d3233303230373030323632385a170d3234303230373030323632385a3045310b3009060355040613025553310b300906035504080c02434131153013060355040a0c0c73776966742d6c69627032703112301006035504030c096c6f63616c686f737430820122300d06092a864886f70d01010105000382010f003082010a0282010100bb2a1008a789ea4f1acfc2b7f0f0c6dbdbee4e5687389bd0fe7ec4f87bc12136949882cbe9805256d2488fb5b111e4d7a3405fd9dc44052b1c4fb733f10519db323592b1b3287aae1b9dd20b6c94cd493c5169dde95491d9eafa2dedafa76a21be80c6987cd0c3274fe891e0449f02981d2c28706347b6d7aae36706ba937561b87713eb4b7047fa838ea2ee146b8bb750dd713d32f000d7378b6ff1a8fb3986d93b78d351010405c989e092759884e5ca73346e0440c0967392f58d456b23dd465b20b3a46ba587883aa1ad7b73b642b9c315154da275cdf095ccfd749755c447d5ddddc92cd74b233cb48075569d833c43234ee0d8e8626dd95a0cc19e13f10203010001300d06092a864886f70d01010b05000382010100143449ecbf722ff298010691eb8c9126f12d7ca63b7352be7102fc018199834a56a703d41ea266192cc46afd11c8245529dc58c2c057adacfe48ccf9e720a60ad13fd1ab71ff07c9e92206d057d653ef8b49828e629a022bcf3f05fc53bd6ad811bfcfa115fba0f7df0914823cfe469dfdf9967e5051f0c004025dc16167aec9018842b8677f3f339d66cb6f68752ed1b1fc482fb2ad05f3f81482bb518a37e7792f81ec4f7738145de19f3bda6a5c4ca0cdfc014eaed88416334da85674de56a8d4551dd063f0541d38e0cbd584afc25bb235bde29d6fbe396fc034585bef4a74711cf9c2b8c682699a090923b7040e36b9a7f55c003ae8cb6ca5e02d0207ca00000f0001040804010081abc044094adfa9363cebaadd1b4affd116070b2b6e49cf921504f69d5d2647d112238a842adf049019e32731829daa092c51d725b6e9f64c87eb21347552be6442b91067b0fee361688cbfb6824af9b423a894a2262fc4b9878f4a5ba2e528d21ce4a8e0a4af4aba6e07a36b47c3ddebe4df8a059bf9f3811496ba7583c1de792c417435430f177ac2da9172eefc2547a5bd59110f907c12c9488d199e693bae70"

        let handshakePacketProtector = try version.newAEAD(clientSecret: clientHandshakeTrafficSecret, serverSecret: serverHandshakeTrafficSecret, perspective: .client, suite: .AESGCM128_SHA256, epoch: .Handshake)

        guard let handshakeHeaderByte = handshakeByteBuffer.getBytes(at: 0, length: 1)?.first else { return XCTFail("No HandshakeHeaderByte") }
        guard let handshakePacketType = PacketType(handshakeHeaderByte) else { return XCTFail("Invalid HandshakeHeaderByte") }
        guard handshakePacketType.isLongHeader else { return XCTFail("Invalid handshake packet type") }
        let handshakeInfo = try handshakeByteBuffer.getLongHeaderPacketNumberOffset(at: 0, isInitial: handshakePacketType == .Initial)
        XCTAssertEqual(handshakeInfo.packetNumberOffset, 17)
        XCTAssertEqual(handshakeInfo.packetLength, 1100)

        // At this point we know the protected header bytes, and the encrypted payload bytes
        guard let handshakeVersion = handshakeByteBuffer.getVersion(at: 1), isSupported(version: version) else { return XCTFail("Invalid Version") }
        XCTAssertEqual(handshakeVersion, version)
        XCTAssertEqual(handshakeVersion, .version1)

        // Unprotect Header
        let unprotectedHandshakeHeaderLength = try handshakeByteBuffer.removeLongHeaderProtection(at: 0, packetNumberOffset: handshakeInfo.packetNumberOffset, sampleSize: 16, using: handshakePacketProtector.opener!)
        XCTAssertEqual(handshakeByteBuffer.viewBytes(at: 0, length: unprotectedHandshakeHeaderLength)?.hexString, expectedUnprotectedHandshakeHeader)
        let handshakePacketNumber = handshakeByteBuffer.getBytes(at: handshakeInfo.packetNumberOffset, length: unprotectedHandshakeHeaderLength - handshakeInfo.packetNumberOffset)
        XCTAssertEqual(handshakePacketNumber, [0x00, 0x00])

        // Decrypt Payload
        try handshakeByteBuffer.decryptBytes(at: unprotectedHandshakeHeaderLength, packetLength: Int(handshakeInfo.packetLength), headerOffset: 0, packetNumber: handshakePacketNumber!, using: handshakePacketProtector.opener!, paddingRemovalStrategy: .doNothing)
        print(handshakeByteBuffer.viewBytes(at: handshakeByteBuffer.readerIndex, length: Int(handshakeInfo.packetLength))!.hexString)

        XCTAssertEqual(handshakeByteBuffer.readableBytesView.hexString, expectedUnprotectedHandshakeHeader + expectedHandshakePayload)
        HeaderByteInspector(handshakeByteBuffer.getBytes(at: handshakeByteBuffer.readerIndex, length: 1)!.first!).inspect()
    }
}
