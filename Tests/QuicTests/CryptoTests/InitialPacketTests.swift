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

final class InitialPacketTests: XCTestCase {

    func testAppendix2ClientInitialHeader() throws {
        let expectedUnprotectedHeader = try Array(hexString: "0xc300000001088394c8f03e5157080000449e00000002")

        let initialHeader = InitialHeader(
            version: .version1,
            destinationID: ConnectionID(with: try Array(hexString: "0x8394c8f03e515708")),
            sourceID: ConnectionID(),
            token: [],
            packetLength: 1182,
            packetNumber: [0x00, 0x00, 0x00, 0x02]
        )

        //print(initialHeader.bytes.hexString)
        //print(expectedUnprotectedHeader.hexString)

        XCTAssertEqual(initialHeader.bytes, expectedUnprotectedHeader)
    }

    func testAppendix2ClientInitialPacketProtection_Manual() throws {
        let version = Version.version1
        let dcid = ConnectionID(with: try Array(hexString: "0x8394c8f03e515708"))
        let cryptoFrame = try Frames.Crypto(offset: VarInt(integerLiteral: 0), data: Array(hexString: "010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578616d706c652e636f6dff01000100000a00080006001d0017001800100007000504616c706e000500050100000000003300260024001d00209370b2c9caa47fbabaf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b0003020304000d0010000e0403050306030203080408050806002d00020101001c00024001003900320408ffffffffffffffff05048000ffff07048000ffff0801100104800075300901100f088394c8f03e51570806048000ffff"))

        let packetProtector = try version.newInitialAEAD(connectionID: dcid, perspective: .client)
        XCTAssertEqual(packetProtector.sealer!.encryptor.key.bytes.hexString, "1f369613dd76d5467730efcbe3b1a22d")
        XCTAssertEqual(packetProtector.sealer!.encryptor.iv!.hexString, "fa044b2f42a3fd3b46fb255c")

        // Construct our Initial Packet
        let initialHeader = InitialHeader(version: version, destinationID: dcid, sourceID: ConnectionID(), token: [], packetNumber: [0x00, 0x00, 0x00, 0x02])
        var initialPacket = InitialPacket(header: initialHeader, payload: [cryptoFrame])

        // Initial Packets get Padded to a certain length
        initialPacket.payload = [cryptoFrame, Frames.Padding(length: 1162 - cryptoFrame.serializedByteCount)]

        XCTAssertEqual(initialPacket.headerBytes, try Array(hexString: "0xc300000001088394c8f03e5157080000449e00000002"))

        // Encrypt the payload
        let encryptedPayload = try packetProtector.sealer!.encryptor.seal(message: initialPacket.serializedPayload, packetNumber: initialHeader.packetNumber, authenticatingData: initialPacket.headerBytes)

        let expectedCiphertext = try Array(hexString: "d1b1c98dd7689fb8ec11d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f3991c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df621230c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c2084dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f89937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c7468449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663ac69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe5896425c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ffef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009ddc324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77fcb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450efc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03adea2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e72404790a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f440591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca06948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f0940054da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd46840647e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241")
        XCTAssertEqual(encryptedPayload.ciphertext.withUnsafeBytes { Array($0) }, expectedCiphertext)

        let expectedTag = try Array(hexString: "e221af44860018ab0856972e194cd934")
        XCTAssertEqual(encryptedPayload.tag.withUnsafeBytes { Array($0) }, expectedTag)

        // Assert that the calculated packetNumberOffset is as expected
        XCTAssertEqual(initialPacket.header.packetNumberOffset, 18)

        // Protect the header
        var protectedHeaderBytes = initialPacket.headerBytes
        try packetProtector.sealer!.headerProtector.applyMask(sample: encryptedPayload.ciphertext.prefix(16), headerBytes: &protectedHeaderBytes, packetNumberOffset: initialPacket.header.packetNumberOffset)
        XCTAssertEqual(protectedHeaderBytes, try Array(hexString: "c000000001088394c8f03e5157080000449e7b9aec34"))

        // Ensure the final packet matches the Appendix
        let expectedFinalPacket = try Array(hexString: "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f3991c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df621230c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c2084dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f89937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c7468449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663ac69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe5896425c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ffef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009ddc324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77fcb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450efc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03adea2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e72404790a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f440591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca06948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f0940054da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd46840647e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241e221af44860018ab0856972e194cd934")

        XCTAssertEqual((protectedHeaderBytes + encryptedPayload.ciphertext.withUnsafeBytes { Array($0) } + encryptedPayload.tag.withUnsafeBytes { Array($0) }), expectedFinalPacket)
    }

    func testAppendix2ClientInitialPacketProtection_Auto() throws {
        let version = Version.version1
        let dcid = ConnectionID(with: try Array(hexString: "0x8394c8f03e515708"))
        let cryptoFrame = try Frames.Crypto(offset: VarInt(integerLiteral: 0), data: Array(hexString: "010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578616d706c652e636f6dff01000100000a00080006001d0017001800100007000504616c706e000500050100000000003300260024001d00209370b2c9caa47fbabaf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b0003020304000d0010000e0403050306030203080408050806002d00020101001c00024001003900320408ffffffffffffffff05048000ffff07048000ffff0801100104800075300901100f088394c8f03e51570806048000ffff"))

        let packetProtector = try version.newInitialAEAD(connectionID: dcid, perspective: .client)
        XCTAssertEqual(packetProtector.sealer!.encryptor.key.bytes.hexString, "1f369613dd76d5467730efcbe3b1a22d")
        XCTAssertEqual(packetProtector.sealer!.encryptor.iv!.hexString, "fa044b2f42a3fd3b46fb255c")

        // Construct our Initial Packet
        let initialHeader = InitialHeader(version: version, destinationID: dcid, sourceID: ConnectionID(), token: [], packetNumber: [0x00, 0x00, 0x00, 0x02])
        var initialPacket = InitialPacket(header: initialHeader, payload: [cryptoFrame])

        // Initial Packets get Padded to a certain length
        initialPacket.payload = [cryptoFrame, Frames.Padding(length: 1162 - cryptoFrame.serializedByteCount)]

        XCTAssertEqual(initialPacket.headerBytes, try Array(hexString: "0xc300000001088394c8f03e5157080000449e00000002"))

        let sealedPacket = try initialPacket.seal(using: packetProtector) // try packetProtector.sealPacket(initialPacket)

        // Ensure the final packet matches the Appendix
        let expectedFinalPacket = try Array(hexString: "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f3991c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df621230c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c2084dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f89937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c7468449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663ac69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe5896425c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ffef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009ddc324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77fcb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450efc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03adea2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e72404790a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f440591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca06948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f0940054da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd46840647e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241e221af44860018ab0856972e194cd934")

        XCTAssertEqual(sealedPacket.protectedHeader + sealedPacket.encryptedPayload, expectedFinalPacket.withUnsafeBytes { Array($0) })
    }

    func testInitialPacketEncryption_Draft29_Auto() throws {
        let dcid = ConnectionID(with: try Array(hexString: "0x18af10fdfa370dd3b3"))
        let scid = ConnectionID(with: try Array(hexString: "0xd0b92e09"))
        let version = Version.versionDraft29
        let initialHeader = InitialHeader(version: version, destinationID: dcid, sourceID: scid, packetNumber: [0x00, 0x07])

        let plaintextCryptoFrame = try Frames.Crypto(offset: VarInt(integerLiteral: 0), data: Array(hexString: "010001160303c1a7ab52c34ba6750648ab7020ed72fe347891126d41aa527bb8cab120f47259000026c02bc02fc02cc030cca9cca8c009c013c00ac014009c009d002f0035c012000a130113021303010000c7000500050100000000000a000a0008001d001700180019000b00020100000d001a0018080404030807080508060401050106010503060302010203ff01000100001000090007066c696270327000120000002b0003020304003300260024001d0020473af2bae35114c75cdaf759e2f8ae4b25d833d7ab115b10ee33ac192b00b93effa500414bf9079472fded4dac080504800800000604800800000704800800000404800c000008024100090100010480007530030245ac0b011a0c000e01040f04d0b92e09"))
        let padding = Frames.Padding(length: 1211 - plaintextCryptoFrame.serializedByteCount)

        let initialPacket = InitialPacket(header: initialHeader, payload: [padding, plaintextCryptoFrame])
        //initialPacket.payload = paddedPayload

        let packetProtector = try version.newInitialAEAD(connectionID: dcid, perspective: .client)

        let sealedPacket = try initialPacket.seal(using: packetProtector)

        let expectedInitialPacketBytes = try Array(hexString: "c8ff00001d0918af10fdfa370dd3b304d0b92e090044cd44bbbfdf74505084f6c2dcbfdb3b4862abaad58676a05b75fb205551b56c3036a5142b679f8d48a65e0c6873780284722211e89324e595bc58e7341916537eb88a6a62daf10104f8e92f1b0d7cb9183d2e58c83bd98f4c251b90adcfbc78cc2922235f44643b4f93cd5dd4336cb83993cdc59aacd422d08f89558562145eb6a802dd806679ff154332210605649211987698fe66956025ed94bdd135315b54b2523c20b603952976c54ccdd64c9773addfae17deb628ec3dbd7e19b3ebaf44e37b342b7f0ca3e598010c582e557e25d8fc1e3908d801104710b8929d7269bbfb82256841bf7089891cdc5d61f0f227dca01ab67b57c00bcb73fc62d2326585c554d40a3f2363ce8da40e5bc68e77831ee8a0ca815fc5297f64acbee4588dd16fbf7633a3eacc9a69c26dc96e7f5ae77654c6d1b83e9de3087d16257f617074c53dcb85b0eb63492a1520afa4f8f0c4078d3f674c24f393fca1602f8edef1c5feac002d221959d6bfdf1cb26791644d17bf6b5bbe846790566b883e65ffa0d0df57c0610f4f5d78367c613f9e6cf76a447917bf0a1cf07efe5beb4180ac2d316565ea2dccf4b59d880d6e09ad33f842e79f91ec61e83433f4ff75c9ecc538a3fb578366c4604e226b100f2b769f32a81f175000cc05ce28a66ecf56129710ebfae04b6bad72acfc25af43330eb54090173b7e0e2cdba3c63c11281f941e57d1c39b5b9263a783ae8128bd592e898565b89b9043a8f3dc10ca5214fafd05d854315e86d71e2374ab6cc7c6903cc9e35cd0de493a1d30d4cc3fb380cc52183a01c5281eb081aa1c9c7d48e1861ce1c62f024b6dcedcf8940c0961d605b79dd3495f8069e6b84ab7e32d7d5943ea95cd169f4df6031e93cd129a593725c5841bcc5970fa4e0ce2ad713330c6ea41aea65f25b92aad30dd5f27fa9fff8fbac82ffc3c5bdb9c20b2186869087fc1ccff04779ccde82078c5479554c054351c2fb3628585f9ab87ab94e6076fa6e10af1ae4ec009ea8a613a90378c97857594ce4612e6f07c486a0cae5799ade6d386c7831394a9da436153553764589b84f7eb6a2ab577028040be8c14afbdb441013b7335a73702c3cb508f06b0831b4708a0e2dbf329ec2970089af33928bea8b89c02b603ffccb170e823320afd30d45eeff68f93227989844795d6345465e3db35c17f096b42c68f1a187db5658fbee4fed802465d94edf2e6e1d8a9b550bfd8ffe737894bca29fee09b74e31aecda421d947997834014423754d7e839ed6fc7017fc5be68df45d08c3196173329749eab2b29197bb353a9e9ab9362d252ee4b514eb288f7467a6d7eaaab7cd449de334fbe61230d4698cdf52465fa78b2a14a647aa107aed426e131fc24d1c10a25c6f43de2abe99176b2e798785b8a98e3b8d46540041279311fb6b158fc0971e4f19200359bad597e8b7287ac44ae8a91b93885fedc430d46f6bbee672a5445863553cf55bec02e9764d46dfc558bac0802a1209018e58e3765b6cbb79f6b6ce3a75877b39407eaae6afc6d43df90787ba49595e507d005c14ac15637f2a5965b0412f2d5301d5f4f0421d311283bc04d7449b8fa59c1cb0d3df9e0f687967b0545c4e2414a186eb5f94b252bff4fbce05ae4db148b61e011132329888154c74c0ec4ed78d22aa39f74d4d793b42da8225ee12b896007c18e5c6f842c1ac46801345b74111a241a4cf14aae630cb7970b51cd")

        XCTAssertEqual(sealedPacket.protectedHeader + sealedPacket.encryptedPayload, expectedInitialPacketBytes)
    }

    func testInitialPacketEncryption_Draft29_Manual() throws {
        let dcid = ConnectionID(with: try Array(hexString: "0x18af10fdfa370dd3b3"))
        let scid = ConnectionID(with: try Array(hexString: "0xd0b92e09"))
        let version = Version.versionDraft29
        let initialHeader = InitialHeader(version: version, destinationID: dcid, sourceID: scid, packetNumber: [0x00, 0x07])

        let plaintextCryptoFrame = try Frames.Crypto(offset: VarInt(integerLiteral: 0), data: Array(hexString: "010001160303c1a7ab52c34ba6750648ab7020ed72fe347891126d41aa527bb8cab120f47259000026c02bc02fc02cc030cca9cca8c009c013c00ac014009c009d002f0035c012000a130113021303010000c7000500050100000000000a000a0008001d001700180019000b00020100000d001a0018080404030807080508060401050106010503060302010203ff01000100001000090007066c696270327000120000002b0003020304003300260024001d0020473af2bae35114c75cdaf759e2f8ae4b25d833d7ab115b10ee33ac192b00b93effa500414bf9079472fded4dac080504800800000604800800000704800800000404800c000008024100090100010480007530030245ac0b011a0c000e01040f04d0b92e09"))
        let padding = Frames.Padding(length: 1211 - plaintextCryptoFrame.serializedByteCount)

        var initialPacket = InitialPacket(header: initialHeader, payload: [padding, plaintextCryptoFrame])
        //initialPacket.payload = paddedPayload

        let unprotectedHeader = initialPacket.headerBytes
        XCTAssertEqual(unprotectedHeader, try Array(hexString: "c1ff00001d0918af10fdfa370dd3b304d0b92e090044cd0007"))

        let packetProtector = try version.newInitialAEAD(connectionID: dcid, perspective: .client)

        // Encrypt the Payload
        XCTAssertEqual(initialHeader.packetNumber, [0x00, 0x07])
        let encryptedData = try packetProtector.encryptPayload(message: initialPacket.serializedPayload, packetNumber: initialHeader.packetNumber, authenticatingData: unprotectedHeader)

        // Protect the header (nonce == 51a3488a8397935207de6a71)
        let sample = Array(Array(encryptedData.ciphertext)[2..<18])
        XCTAssertEqual(sample, try Array(hexString: "74505084f6c2dcbfdb3b4862abaad586"))
        let pno = try unprotectedHeader.calculateLongHeaderPacketNumberOffset()
        XCTAssertEqual(pno, 23)
        var protectedHeader = unprotectedHeader
        try packetProtector.applyHeaderProtection(sample: sample, headerBytes: &protectedHeader, packetNumberOffset: pno)

        XCTAssertEqual(protectedHeader, try Array(hexString: "c8ff00001d0918af10fdfa370dd3b304d0b92e090044cd44bb"))

        let expectedInitialPacketBytes = try Array(hexString: "c8ff00001d0918af10fdfa370dd3b304d0b92e090044cd44bbbfdf74505084f6c2dcbfdb3b4862abaad58676a05b75fb205551b56c3036a5142b679f8d48a65e0c6873780284722211e89324e595bc58e7341916537eb88a6a62daf10104f8e92f1b0d7cb9183d2e58c83bd98f4c251b90adcfbc78cc2922235f44643b4f93cd5dd4336cb83993cdc59aacd422d08f89558562145eb6a802dd806679ff154332210605649211987698fe66956025ed94bdd135315b54b2523c20b603952976c54ccdd64c9773addfae17deb628ec3dbd7e19b3ebaf44e37b342b7f0ca3e598010c582e557e25d8fc1e3908d801104710b8929d7269bbfb82256841bf7089891cdc5d61f0f227dca01ab67b57c00bcb73fc62d2326585c554d40a3f2363ce8da40e5bc68e77831ee8a0ca815fc5297f64acbee4588dd16fbf7633a3eacc9a69c26dc96e7f5ae77654c6d1b83e9de3087d16257f617074c53dcb85b0eb63492a1520afa4f8f0c4078d3f674c24f393fca1602f8edef1c5feac002d221959d6bfdf1cb26791644d17bf6b5bbe846790566b883e65ffa0d0df57c0610f4f5d78367c613f9e6cf76a447917bf0a1cf07efe5beb4180ac2d316565ea2dccf4b59d880d6e09ad33f842e79f91ec61e83433f4ff75c9ecc538a3fb578366c4604e226b100f2b769f32a81f175000cc05ce28a66ecf56129710ebfae04b6bad72acfc25af43330eb54090173b7e0e2cdba3c63c11281f941e57d1c39b5b9263a783ae8128bd592e898565b89b9043a8f3dc10ca5214fafd05d854315e86d71e2374ab6cc7c6903cc9e35cd0de493a1d30d4cc3fb380cc52183a01c5281eb081aa1c9c7d48e1861ce1c62f024b6dcedcf8940c0961d605b79dd3495f8069e6b84ab7e32d7d5943ea95cd169f4df6031e93cd129a593725c5841bcc5970fa4e0ce2ad713330c6ea41aea65f25b92aad30dd5f27fa9fff8fbac82ffc3c5bdb9c20b2186869087fc1ccff04779ccde82078c5479554c054351c2fb3628585f9ab87ab94e6076fa6e10af1ae4ec009ea8a613a90378c97857594ce4612e6f07c486a0cae5799ade6d386c7831394a9da436153553764589b84f7eb6a2ab577028040be8c14afbdb441013b7335a73702c3cb508f06b0831b4708a0e2dbf329ec2970089af33928bea8b89c02b603ffccb170e823320afd30d45eeff68f93227989844795d6345465e3db35c17f096b42c68f1a187db5658fbee4fed802465d94edf2e6e1d8a9b550bfd8ffe737894bca29fee09b74e31aecda421d947997834014423754d7e839ed6fc7017fc5be68df45d08c3196173329749eab2b29197bb353a9e9ab9362d252ee4b514eb288f7467a6d7eaaab7cd449de334fbe61230d4698cdf52465fa78b2a14a647aa107aed426e131fc24d1c10a25c6f43de2abe99176b2e798785b8a98e3b8d46540041279311fb6b158fc0971e4f19200359bad597e8b7287ac44ae8a91b93885fedc430d46f6bbee672a5445863553cf55bec02e9764d46dfc558bac0802a1209018e58e3765b6cbb79f6b6ce3a75877b39407eaae6afc6d43df90787ba49595e507d005c14ac15637f2a5965b0412f2d5301d5f4f0421d311283bc04d7449b8fa59c1cb0d3df9e0f687967b0545c4e2414a186eb5f94b252bff4fbce05ae4db148b61e011132329888154c74c0ec4ed78d22aa39f74d4d793b42da8225ee12b896007c18e5c6f842c1ac46801345b74111a241a4cf14aae630cb7970b51cd")

        XCTAssertEqual(protectedHeader + encryptedData.ciphertext + encryptedData.tag, expectedInitialPacketBytes)
    }

    func testInitialPacketDecryption_Draft29_Manual() throws {
        let packetBytes = try Array(hexString: "c8ff00001d0918af10fdfa370dd3b304d0b92e090044cd44bbbfdf74505084f6c2dcbfdb3b4862abaad58676a05b75fb205551b56c3036a5142b679f8d48a65e0c6873780284722211e89324e595bc58e7341916537eb88a6a62daf10104f8e92f1b0d7cb9183d2e58c83bd98f4c251b90adcfbc78cc2922235f44643b4f93cd5dd4336cb83993cdc59aacd422d08f89558562145eb6a802dd806679ff154332210605649211987698fe66956025ed94bdd135315b54b2523c20b603952976c54ccdd64c9773addfae17deb628ec3dbd7e19b3ebaf44e37b342b7f0ca3e598010c582e557e25d8fc1e3908d801104710b8929d7269bbfb82256841bf7089891cdc5d61f0f227dca01ab67b57c00bcb73fc62d2326585c554d40a3f2363ce8da40e5bc68e77831ee8a0ca815fc5297f64acbee4588dd16fbf7633a3eacc9a69c26dc96e7f5ae77654c6d1b83e9de3087d16257f617074c53dcb85b0eb63492a1520afa4f8f0c4078d3f674c24f393fca1602f8edef1c5feac002d221959d6bfdf1cb26791644d17bf6b5bbe846790566b883e65ffa0d0df57c0610f4f5d78367c613f9e6cf76a447917bf0a1cf07efe5beb4180ac2d316565ea2dccf4b59d880d6e09ad33f842e79f91ec61e83433f4ff75c9ecc538a3fb578366c4604e226b100f2b769f32a81f175000cc05ce28a66ecf56129710ebfae04b6bad72acfc25af43330eb54090173b7e0e2cdba3c63c11281f941e57d1c39b5b9263a783ae8128bd592e898565b89b9043a8f3dc10ca5214fafd05d854315e86d71e2374ab6cc7c6903cc9e35cd0de493a1d30d4cc3fb380cc52183a01c5281eb081aa1c9c7d48e1861ce1c62f024b6dcedcf8940c0961d605b79dd3495f8069e6b84ab7e32d7d5943ea95cd169f4df6031e93cd129a593725c5841bcc5970fa4e0ce2ad713330c6ea41aea65f25b92aad30dd5f27fa9fff8fbac82ffc3c5bdb9c20b2186869087fc1ccff04779ccde82078c5479554c054351c2fb3628585f9ab87ab94e6076fa6e10af1ae4ec009ea8a613a90378c97857594ce4612e6f07c486a0cae5799ade6d386c7831394a9da436153553764589b84f7eb6a2ab577028040be8c14afbdb441013b7335a73702c3cb508f06b0831b4708a0e2dbf329ec2970089af33928bea8b89c02b603ffccb170e823320afd30d45eeff68f93227989844795d6345465e3db35c17f096b42c68f1a187db5658fbee4fed802465d94edf2e6e1d8a9b550bfd8ffe737894bca29fee09b74e31aecda421d947997834014423754d7e839ed6fc7017fc5be68df45d08c3196173329749eab2b29197bb353a9e9ab9362d252ee4b514eb288f7467a6d7eaaab7cd449de334fbe61230d4698cdf52465fa78b2a14a647aa107aed426e131fc24d1c10a25c6f43de2abe99176b2e798785b8a98e3b8d46540041279311fb6b158fc0971e4f19200359bad597e8b7287ac44ae8a91b93885fedc430d46f6bbee672a5445863553cf55bec02e9764d46dfc558bac0802a1209018e58e3765b6cbb79f6b6ce3a75877b39407eaae6afc6d43df90787ba49595e507d005c14ac15637f2a5965b0412f2d5301d5f4f0421d311283bc04d7449b8fa59c1cb0d3df9e0f687967b0545c4e2414a186eb5f94b252bff4fbce05ae4db148b61e011132329888154c74c0ec4ed78d22aa39f74d4d793b42da8225ee12b896007c18e5c6f842c1ac46801345b74111a241a4cf14aae630cb7970b51cd")
        var initialPacketBytes = packetBytes

        let firstByte = initialPacketBytes.first!
        let type = PacketType(firstByte)
        XCTAssertEqual(type, .Initial)

        let version = Array(initialPacketBytes[1...4]).withUnsafeBufferPointer({ ptr in Version(with: ptr) })
        XCTAssertEqual(version, .versionDraft29)

        // Simulate Buffer Consumption
        initialPacketBytes.removeFirst(5)

        let dcid = ConnectionID(with: initialPacketBytes.consumeQuicVarIntLengthPrefixedData().bytes)
        XCTAssertEqual(dcid.rawValue, try Array(hexString: "0x18af10fdfa370dd3b3"))

        let scid = ConnectionID(with: initialPacketBytes.consumeQuicVarIntLengthPrefixedData().bytes)
        XCTAssertEqual(scid.rawValue, try Array(hexString: "0xd0b92e09"))

        let token = initialPacketBytes.consumeQuicVarIntLengthPrefixedData()
        XCTAssertEqual(token.bytes, [])
        XCTAssertEqual(token.value, 0)

        let packetLength = initialPacketBytes.consumeQuicVarInt()!
        XCTAssertEqual(Int(packetLength), initialPacketBytes.count)

        let initialHeader = InitialHeader(version: version, destinationID: dcid, sourceID: scid, token: token.bytes, packetLength: packetLength, packetNumber: Array(initialPacketBytes[..<4]))

        let packetProtector = try version.newInitialAEAD(connectionID: dcid, perspective: .server)

        let sample = Array(initialPacketBytes[4..<20])
        XCTAssertEqual(sample, try Array(hexString: "74505084f6c2dcbfdb3b4862abaad586"))
        var headerBytes = Array(packetBytes[0..<27])
        XCTAssertEqual(headerBytes, try Array(hexString: "c8ff00001d0918af10fdfa370dd3b304d0b92e090044cd44bbbfdf"))
        try packetProtector.removeHeaderProtection(sample: sample, headerBytes: &headerBytes, packetNumberOffset: initialHeader.packetNumberOffset)

        let pnl = PacketNumberLength(rawValue: headerBytes.first! & PacketNumberLength.mask)!
        XCTAssertEqual(pnl, ._2)

        let cipherText = Array(initialPacketBytes[pnl.bytesToRead...])
        let unprotectedHeader = headerBytes // Array(headerBytes.dropLast(4 - pnl.bytesToRead))
        let packetNumber = Array(unprotectedHeader.suffix(pnl.bytesToRead))
        XCTAssertEqual(unprotectedHeader, try Array(hexString: "c1ff00001d0918af10fdfa370dd3b304d0b92e090044cd0007"))

        let decryptedPayload = try packetProtector.decryptPayload(cipherText, packetNumber: packetNumber, authenticatingData: unprotectedHeader)

        let packetProtector2 = try version.newInitialAEAD(connectionID: dcid, perspective: .client)
        let reEncrypted = try packetProtector2.sealer!.encryptor.seal(message: decryptedPayload, packetNumber: [0x00, 0x07], authenticatingData: unprotectedHeader)
        XCTAssertEqual(Array(reEncrypted.ciphertext + reEncrypted.tag), cipherText)

        let plaintextCryptoFrame = try Array(hexString: "0600411a010001160303c1a7ab52c34ba6750648ab7020ed72fe347891126d41aa527bb8cab120f47259000026c02bc02fc02cc030cca9cca8c009c013c00ac014009c009d002f0035c012000a130113021303010000c7000500050100000000000a000a0008001d001700180019000b00020100000d001a0018080404030807080508060401050106010503060302010203ff01000100001000090007066c696270327000120000002b0003020304003300260024001d0020473af2bae35114c75cdaf759e2f8ae4b25d833d7ab115b10ee33ac192b00b93effa500414bf9079472fded4dac080504800800000604800800000704800800000404800c000008024100090100010480007530030245ac0b011a0c000e01040f04d0b92e09")
        XCTAssertEqual(plaintextCryptoFrame, Array(decryptedPayload.drop(while: { $0 == 0 })))
    }

    func testInitialPacketDecryption_Draft29_Automatic() throws {
        let packetBytes = try Array(hexString: "c8ff00001d0918af10fdfa370dd3b304d0b92e090044cd44bbbfdf74505084f6c2dcbfdb3b4862abaad58676a05b75fb205551b56c3036a5142b679f8d48a65e0c6873780284722211e89324e595bc58e7341916537eb88a6a62daf10104f8e92f1b0d7cb9183d2e58c83bd98f4c251b90adcfbc78cc2922235f44643b4f93cd5dd4336cb83993cdc59aacd422d08f89558562145eb6a802dd806679ff154332210605649211987698fe66956025ed94bdd135315b54b2523c20b603952976c54ccdd64c9773addfae17deb628ec3dbd7e19b3ebaf44e37b342b7f0ca3e598010c582e557e25d8fc1e3908d801104710b8929d7269bbfb82256841bf7089891cdc5d61f0f227dca01ab67b57c00bcb73fc62d2326585c554d40a3f2363ce8da40e5bc68e77831ee8a0ca815fc5297f64acbee4588dd16fbf7633a3eacc9a69c26dc96e7f5ae77654c6d1b83e9de3087d16257f617074c53dcb85b0eb63492a1520afa4f8f0c4078d3f674c24f393fca1602f8edef1c5feac002d221959d6bfdf1cb26791644d17bf6b5bbe846790566b883e65ffa0d0df57c0610f4f5d78367c613f9e6cf76a447917bf0a1cf07efe5beb4180ac2d316565ea2dccf4b59d880d6e09ad33f842e79f91ec61e83433f4ff75c9ecc538a3fb578366c4604e226b100f2b769f32a81f175000cc05ce28a66ecf56129710ebfae04b6bad72acfc25af43330eb54090173b7e0e2cdba3c63c11281f941e57d1c39b5b9263a783ae8128bd592e898565b89b9043a8f3dc10ca5214fafd05d854315e86d71e2374ab6cc7c6903cc9e35cd0de493a1d30d4cc3fb380cc52183a01c5281eb081aa1c9c7d48e1861ce1c62f024b6dcedcf8940c0961d605b79dd3495f8069e6b84ab7e32d7d5943ea95cd169f4df6031e93cd129a593725c5841bcc5970fa4e0ce2ad713330c6ea41aea65f25b92aad30dd5f27fa9fff8fbac82ffc3c5bdb9c20b2186869087fc1ccff04779ccde82078c5479554c054351c2fb3628585f9ab87ab94e6076fa6e10af1ae4ec009ea8a613a90378c97857594ce4612e6f07c486a0cae5799ade6d386c7831394a9da436153553764589b84f7eb6a2ab577028040be8c14afbdb441013b7335a73702c3cb508f06b0831b4708a0e2dbf329ec2970089af33928bea8b89c02b603ffccb170e823320afd30d45eeff68f93227989844795d6345465e3db35c17f096b42c68f1a187db5658fbee4fed802465d94edf2e6e1d8a9b550bfd8ffe737894bca29fee09b74e31aecda421d947997834014423754d7e839ed6fc7017fc5be68df45d08c3196173329749eab2b29197bb353a9e9ab9362d252ee4b514eb288f7467a6d7eaaab7cd449de334fbe61230d4698cdf52465fa78b2a14a647aa107aed426e131fc24d1c10a25c6f43de2abe99176b2e798785b8a98e3b8d46540041279311fb6b158fc0971e4f19200359bad597e8b7287ac44ae8a91b93885fedc430d46f6bbee672a5445863553cf55bec02e9764d46dfc558bac0802a1209018e58e3765b6cbb79f6b6ce3a75877b39407eaae6afc6d43df90787ba49595e507d005c14ac15637f2a5965b0412f2d5301d5f4f0421d311283bc04d7449b8fa59c1cb0d3df9e0f687967b0545c4e2414a186eb5f94b252bff4fbce05ae4db148b61e011132329888154c74c0ec4ed78d22aa39f74d4d793b42da8225ee12b896007c18e5c6f842c1ac46801345b74111a241a4cf14aae630cb7970b51cd")

        let version = Version.versionDraft29
        let dcid = ConnectionID(with: try Array(hexString: "0x18af10fdfa370dd3b3"))

        let packetProtector = try version.newInitialAEAD(connectionID: dcid, perspective: .server)
        let pno = try packetBytes.calculateLongHeaderPacketNumberOffset()
        let results = try packetProtector.open(bytes: packetBytes, packetNumberOffset: pno)

        /// Assert header is what we expect
        XCTAssertEqual(results.header, try Array(hexString: "c1ff00001d0918af10fdfa370dd3b304d0b92e090044cd0007"))

        /// Assert the decrypted payload is what we expect
        let plaintextCryptoFrame = try Array(hexString: "0600411a010001160303c1a7ab52c34ba6750648ab7020ed72fe347891126d41aa527bb8cab120f47259000026c02bc02fc02cc030cca9cca8c009c013c00ac014009c009d002f0035c012000a130113021303010000c7000500050100000000000a000a0008001d001700180019000b00020100000d001a0018080404030807080508060401050106010503060302010203ff01000100001000090007066c696270327000120000002b0003020304003300260024001d0020473af2bae35114c75cdaf759e2f8ae4b25d833d7ab115b10ee33ac192b00b93effa500414bf9079472fded4dac080504800800000604800800000704800800000404800c000008024100090100010480007530030245ac0b011a0c000e01040f04d0b92e09")
        XCTAssertEqual(plaintextCryptoFrame, Array(results.payload.drop(while: { $0 == 0 })))
    }

    func testPacketNumberOffset_InitialHeader() throws {
        let bytes = try Array(hexString: "c8ff00001d0918af10fdfa370dd3b304d0b92e090044cd44bbbfdf74505084f6c2dcbfdb3b4862abaad58676")
        let pno = try bytes.calculateLongHeaderPacketNumberOffset()
        XCTAssertEqual(pno, 23)
    }
}
