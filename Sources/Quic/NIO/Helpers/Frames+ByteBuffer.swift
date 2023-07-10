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

extension ByteBuffer {
    /// Reads / Consumes Zero Byte Padding from the head of the ByteBuffer
    ///
    /// - returns: The number of Zero byte Padding frames that were consumed
    //@inlinable
    @discardableResult
    mutating func readPaddingFrame() -> Int {
        //print("Attempting to remove padding frame:")
        //print(self.readableBytesView.hexString)
        if let endIndex = self.readableBytesView[self.readerIndex...].firstIndex(where: { $0 != 0x00 }) {
            self.moveReaderIndex(forwardBy: endIndex - self.readerIndex)
            return endIndex - self.readerIndex
        } else {
            let paddingCount = self.readableBytes
            self.moveReaderIndex(forwardBy: self.readableBytes)
            return paddingCount
        }
    }

    /// Reads a Ping Frame
    ///
    /// - returns: A `Ping` frame deserialized from this `ByteBuffer` or `nil` if there isn't a complete / valid Ping frame present
    //@inlinable
    mutating func readPingFrame() -> Frames.Ping? {
        return self.rewindReaderOnNil { `self` -> Frames.Ping? in
            guard let type = self.readBytes(length: 1)?.first, type == Frames.Ping.type else { return nil }

            return Frames.Ping()
        }
    }

    /// Reads an ACK Frame
    ///
    /// - returns: A `ACK` frame deserialized from this `ByteBuffer` or `nil` if there isn't a complete / valid ACK frame present
    //@inlinable
    mutating func readACKFrame() -> Frames.ACK? {
        return self.rewindReaderOnNil { `self` -> Frames.ACK? in
            guard let type = self.readBytes(length: 1)?.first else { return nil }
            guard type == 0x02 || type == 0x03 else { return nil }
            guard let largestAcked = self.readQuicVarInt() else { return nil }
            guard let ackDelay = self.readQuicVarInt() else { return nil }
            guard let ackRangeCount = self.readQuicVarInt() else { return nil }
            guard let firstAckRange = self.readQuicVarInt() else { return nil }

            var ackRanges: [Frames.ACK.ACKRange] = []
            for _ in 0..<ackRangeCount {
                guard let gap = self.readQuicVarInt() else { return nil }
                guard let range = self.readQuicVarInt() else { return nil }
                ackRanges.append(
                    Frames.ACK.ACKRange(
                        gap: VarInt(integerLiteral: gap),
                        rangeLength: VarInt(integerLiteral: range)
                    )
                )
            }

            let ecnCounts: Frames.ACK.ECNCounts?
            if type == 0x03 {
                guard let ect0 = self.readQuicVarInt() else { return nil }
                guard let ect1 = self.readQuicVarInt() else { return nil }
                guard let ecnCE = self.readQuicVarInt() else { return nil }
                ecnCounts = Frames.ACK.ECNCounts(
                    ect0: VarInt(integerLiteral: ect0),
                    ect1: VarInt(integerLiteral: ect1),
                    ecnCE: VarInt(integerLiteral: ecnCE)
                )
            } else {
                ecnCounts = nil
            }

            return Frames.ACK(
                largestAcknowledged: VarInt(integerLiteral: largestAcked),
                delay: VarInt(integerLiteral: ackDelay),
                firstAckRange: VarInt(integerLiteral: firstAckRange),
                ranges: ackRanges,
                ecnCounts: ecnCounts
            )
        }
    }

    /// Reads a StopSending Frame
    ///
    /// - returns: A `StopSending` frame deserialized from this `ByteBuffer` or `nil` if there isn't a complete / valid StopSending frame present
    //@inlinable
    mutating func readStopSendingFrame() -> Frames.StopSending? {
        return self.rewindReaderOnNil { `self` -> Frames.StopSending? in
            guard let type = self.readBytes(length: 1)?.first, type == Frames.StopSending.type else { return nil }
            guard let streamID = self.readQuicVarInt() else { return nil }
            guard let appError = self.readQuicVarInt() else { return nil }

            return Frames.StopSending(
                streamID: StreamID(rawValue: VarInt(integerLiteral: streamID)),
                applicationProtocolErrorCode: VarInt(integerLiteral: appError)
            )
        }
    }

    /// Reads a Crypto Frame
    ///
    /// - returns: A `Crypto` frame deserialized from this `ByteBuffer` or `nil` if there isn't a complete / valid Crypto frame present
    //@inlinable
    mutating func readCryptoFrame() -> Frames.Crypto? {
        return self.rewindReaderOnNil { `self` -> Frames.Crypto? in
            guard let type = self.readBytes(length: 1)?.first, type == Frames.Crypto.type else { return nil }
            guard let offset = self.readQuicVarInt() else { return nil }
            guard let length = self.readQuicVarInt() else { return nil }
            guard let data = self.readBytes(length: Int(length)) else { return nil }

            return Frames.Crypto(
                offset: VarInt(integerLiteral: offset),
                data: data
            )
        }
    }

    /// Reads a NewToken Frame
    ///
    /// - returns: A `NewToken` frame deserialized from this `ByteBuffer` or `nil` if there isn't a complete / valid NewToken frame present
    //@inlinable
    mutating func readNewTokenFrame() -> Frames.NewToken? {
        return self.rewindReaderOnNil { `self` -> Frames.NewToken? in
            guard let type = self.readBytes(length: 1)?.first, type == Frames.NewToken.type else { return nil }
            guard let length = self.readQuicVarInt() else { return nil }
            guard let token = self.readBytes(length: Int(length)) else { return nil }

            return Frames.NewToken(token: token)
        }
    }

    /// Reads a Stream Frame
    ///
    /// - returns: A `Stream` frame deserialized from this `ByteBuffer` or `nil` if there isn't a complete / valid Stream frame present
    //@inlinable
    mutating func readStreamFrame() -> Frames.Stream? {
        return self.rewindReaderOnNil { `self` -> Frames.Stream? in
            guard let firstByte = self.readBytes(length: 1)?.first else { return nil }
            guard let streamID = self.readQuicVarInt() else { return nil }

            let offset: VarInt?
            if (firstByte & 0x04) == 4 {
                guard let off = self.readQuicVarInt() else { return nil }
                offset = VarInt(integerLiteral: off)
            } else { offset = nil }

            let length: VarInt?
            if (firstByte & 0x02) == 2 {
                guard let len = self.readQuicVarInt() else { return nil }
                length = VarInt(integerLiteral: len)
            } else { length = nil }

            let fin = (firstByte & 0x01) == 1

            let payload: ByteBuffer
            if let length {
                guard let p = self.readSlice(length: Int(length.rawValue)) else { return nil }
                payload = p
            } else {
                guard let p = self.readSlice(length: self.readableBytes) else { return nil }
                payload = p
            }

            return Frames.Stream(
                streamID: StreamID(rawValue: VarInt(integerLiteral: streamID)),
                offset: offset,
                length: length,
                fin: fin,
                data: payload
            )
        }
    }

    /// Reads a ResetStream Frame
    ///
    /// - returns: A `ResetStream` frame deserialized from this `ByteBuffer` or `nil` if there isn't a complete / valid ResetStream frame present
    //@inlinable
    mutating func readResetStreamFrame() -> Frames.ResetStream? {
        return self.rewindReaderOnNil { `self` -> Frames.ResetStream? in
            guard let type = self.readBytes(length: 1)?.first, type == Frames.ResetStream.type else { return nil }
            guard let streamID = self.readQuicVarInt() else { return nil }
            guard let appError = self.readQuicVarInt() else { return nil }
            guard let finalSize = self.readQuicVarInt() else { return nil }

            return Frames.ResetStream(
                streamID: StreamID(rawValue: VarInt(integerLiteral: streamID)),
                applicationProtocolErrorCode: VarInt(integerLiteral: appError),
                finalSize: VarInt(integerLiteral: finalSize)
            )
        }
    }

    /// Reads a MaxData Frame
    ///
    /// - returns: A `MaxData` frame deserialized from this `ByteBuffer` or `nil` if there isn't a complete / valid MaxData frame present
    //@inlinable
    mutating func readMaxDataFrame() -> Frames.MaxData? {
        return self.rewindReaderOnNil { `self` -> Frames.MaxData? in
            guard let type = self.readBytes(length: 1)?.first, type == Frames.MaxData.type else { return nil }
            guard let maxData = self.readQuicVarInt() else { return nil }

            return Frames.MaxData(maximumData: VarInt(integerLiteral: maxData))
        }
    }

    /// Reads a MaxStreamData Frame
    ///
    /// - returns: A `MaxStreamData` frame deserialized from this `ByteBuffer` or `nil` if there isn't a complete / valid MaxStreamData frame present
    //@inlinable
    mutating func readMaxStreamDataFrame() -> Frames.MaxStreamData? {
        return self.rewindReaderOnNil { `self` -> Frames.MaxStreamData? in
            guard let type = self.readBytes(length: 1)?.first, type == Frames.MaxStreamData.type else { return nil }
            guard let streamID = self.readQuicVarInt() else { return nil }
            guard let maxStreamData = self.readQuicVarInt() else { return nil }

            return Frames.MaxStreamData(
                streamID: StreamID(rawValue: VarInt(integerLiteral: streamID)),
                maximumStreamData: VarInt(integerLiteral: maxStreamData)
            )
        }
    }

    /// Reads a MaxStreams Frame
    ///
    /// - returns: A `MaxStreams` frame deserialized from this `ByteBuffer` or `nil` if there isn't a complete / valid MaxStreams frame present
    //@inlinable
    mutating func readMaxStreamsFrame() -> Frames.MaxStreams? {
        return self.rewindReaderOnNil { `self` -> Frames.MaxStreams? in
            guard let type = self.readBytes(length: 1)?.first else { return nil }
            guard let streamType = Frames.MaxStreams.StreamType(rawValue: type) else { return nil }
            guard let maxStreams = self.readQuicVarInt() else { return nil }

            return Frames.MaxStreams(
                streamType: streamType,
                maximumStreams: VarInt(integerLiteral: maxStreams)
            )
        }
    }

    /// Reads a DataBlocked Frame
    ///
    /// - returns: A `DataBlocked` frame deserialized from this `ByteBuffer` or `nil` if there isn't a complete / valid DataBlocked frame present
    //@inlinable
    mutating func readDataBlockedFrame() -> Frames.DataBlocked? {
        return self.rewindReaderOnNil { `self` -> Frames.DataBlocked? in
            guard let type = self.readBytes(length: 1)?.first, type == Frames.DataBlocked.type else { return nil }
            guard let maxData = self.readQuicVarInt() else { return nil }

            return Frames.DataBlocked(maximumData: VarInt(integerLiteral: maxData))
        }
    }

    /// Reads a StreamDataBlocked Frame
    ///
    /// - returns: A `StreamDataBlocked` frame deserialized from this `ByteBuffer` or `nil` if there isn't a complete / valid StreamDataBlocked frame present
    //@inlinable
    mutating func readStreamDataBlockedFrame() -> Frames.StreamDataBlocked? {
        return self.rewindReaderOnNil { `self` -> Frames.StreamDataBlocked? in
            guard let type = self.readBytes(length: 1)?.first, type == Frames.StreamDataBlocked.type else { return nil }
            guard let streamID = self.readQuicVarInt() else { return nil }
            guard let maxStreamData = self.readQuicVarInt() else { return nil }

            return Frames.StreamDataBlocked(
                streamID: StreamID(rawValue: VarInt(integerLiteral: streamID)),
                maximumStreamData: VarInt(integerLiteral: maxStreamData)
            )
        }
    }

    /// Reads a StreamsBlocked Frame
    ///
    /// - returns: A `StreamsBlocked` frame deserialized from this `ByteBuffer` or `nil` if there isn't a complete / valid StreamsBlocked frame present
    //@inlinable
    mutating func readStreamsBlockedFrame() -> Frames.StreamsBlocked? {
        return self.rewindReaderOnNil { `self` -> Frames.StreamsBlocked? in
            guard let type = self.readBytes(length: 1)?.first else { return nil }
            guard let streamType = Frames.StreamsBlocked.StreamType(rawValue: type) else { return nil }
            guard let maxStreams = self.readQuicVarInt() else { return nil }

            return Frames.StreamsBlocked(
                streamType: streamType,
                maximumStreams: VarInt(integerLiteral: maxStreams)
            )
        }
    }

    /// Reads a NewConnectionID Frame
    ///
    /// - returns: A `NewConnectionID` frame deserialized from this `ByteBuffer` or `nil` if there isn't a complete / valid NewConnectionID frame present
    //@inlinable
    mutating func readNewConnectionIDFrame() -> Frames.NewConnectionID? {
        return self.rewindReaderOnNil { `self` -> Frames.NewConnectionID? in
            guard let type = self.readBytes(length: 1)?.first, type == Frames.NewConnectionID.type else { return nil }
            guard let seqNum = self.readQuicVarInt() else { return nil }
            guard let retirePT = self.readQuicVarInt() else { return nil }
            guard let length = self.readInteger(endianness: .big, as: UInt8.self), length >= 1, length <= 20 else { return nil }
            guard let cid = self.readBytes(length: Int(length)) else { return nil }
            guard let srt = self.readBytes(length: 16) else { return nil }

            return Frames.NewConnectionID(
                sequenceNumber: VarInt(integerLiteral: seqNum),
                retirePriorTo: VarInt(integerLiteral: retirePT),
                connectionID: ConnectionID(with: cid),
                statelessResetToken: srt
            )
        }
    }

    /// Reads a RetireConnectionID Frame
    ///
    /// - returns: A `RetireConnectionID` frame deserialized from this `ByteBuffer` or `nil` if there isn't a complete / valid RetireConnectionID frame present
    //@inlinable
    mutating func readRetireConnectionIDFrame() -> Frames.RetireConnectionID? {
        return self.rewindReaderOnNil { `self` -> Frames.RetireConnectionID? in
            guard let type = self.readBytes(length: 1)?.first, type == Frames.RetireConnectionID.type else { return nil }
            guard let seqNum = self.readQuicVarInt() else { return nil }

            return Frames.RetireConnectionID(sequenceNumber: VarInt(integerLiteral: seqNum))
        }
    }

    /// Reads a PathChallenge Frame
    ///
    /// - returns: A `PathChallenge` frame deserialized from this `ByteBuffer` or `nil` if there isn't a complete / valid PathChallenge frame present
    //@inlinable
    mutating func readPathChallengeFrame() -> Frames.PathChallenge? {
        return self.rewindReaderOnNil { `self` -> Frames.PathChallenge? in
            guard let type = self.readBytes(length: 1)?.first, type == Frames.PathChallenge.type else { return nil }
            guard let data = self.readBytes(length: 8) else { return nil }

            return Frames.PathChallenge(data: data)
        }
    }

    /// Reads a PathResponse Frame
    ///
    /// - returns: A `PathResponse` frame deserialized from this `ByteBuffer` or `nil` if there isn't a complete / valid PathResponse frame present
    //@inlinable
    mutating func readPathResponseFrame() -> Frames.PathResponse? {
        return self.rewindReaderOnNil { `self` -> Frames.PathResponse? in
            guard let type = self.readBytes(length: 1)?.first, type == Frames.PathResponse.type else { return nil }
            guard let data = self.readBytes(length: 8) else { return nil }

            return Frames.PathResponse(data: data)
        }
    }

    /// Reads a ConnectionClose Frame
    ///
    /// - returns: A `ConnectionClose` frame deserialized from this `ByteBuffer` or `nil` if there isn't a complete / valid ConnectionClose frame present
    //@inlinable
    mutating func readConnectionCloseFrame() -> Frames.ConnectionClose? {
        return self.rewindReaderOnNil { `self` -> Frames.ConnectionClose? in
            guard let type = self.readBytes(length: 1)?.first else { return nil }
            guard let closeType = Frames.ConnectionClose.CloseType(rawValue: type) else { return nil }
            guard let errorCode = self.readQuicVarInt() else { return nil }

            let frameType: VarInt?
            if closeType == .quic {
                guard let fType = self.readQuicVarInt() else { return nil }
                frameType = VarInt(integerLiteral: fType)
            } else { frameType = nil }

            guard let reasonPhraseLength = self.readQuicVarInt() else { return nil }
            guard let reasonPhrase = self.readString(length: Int(reasonPhraseLength)) else { return nil }

            return Frames.ConnectionClose(
                closeType: closeType,
                errorCode: VarInt(integerLiteral: errorCode),
                frameType: frameType,
                reasonPhrase: reasonPhrase
            )
        }
    }

    /// Reads a HandshakeDone Frame
    ///
    /// - returns: A `HandshakeDone` frame deserialized from this `ByteBuffer` or `nil` if there isn't a complete / valid HandshakeDone frame present
    //@inlinable
    mutating func readHandshakeDoneFrame() -> Frames.HandshakeDone? {
        return self.rewindReaderOnNil { `self` -> Frames.HandshakeDone? in
            guard let type = self.readBytes(length: 1)?.first, type == Frames.HandshakeDone.type else { return nil }

            return Frames.HandshakeDone()
        }
    }
}

extension ByteBuffer {
    internal mutating func parsePayloadIntoFrames() throws -> (frames: [any Frame], leftoverBytes: ByteBuffer?) {
        let result = self.rewindReaderOnNil { `self` -> (frames: [any Frame], leftoverBytes: ByteBuffer?)? in
            var frames: [any Frame] = []
            var leftoverBytes: ByteBuffer?

            readLoop: while self.readableBytes > 0 {

                guard let firstByte = self.getBytes(at: self.readerIndex, length: 1)?.first else { break readLoop }
                switch firstByte {
                    case Frames.Padding.type: //0x00
                        self.readPaddingFrame()
                    //frames.append(Frames.Padding(length: padding))
                    case Frames.Ping.type: // 0x01
                        guard let ping = self.readPingFrame() else { break readLoop }
                        frames.append(ping)
                    case 0x02...0x03: // ACK Frames
                        guard let ack = self.readACKFrame() else { break readLoop }
                        frames.append(ack)
                    case Frames.ResetStream.type: // 0x04
                        guard let rs = self.readResetStreamFrame() else { break readLoop }
                        frames.append(rs)
                    case Frames.StopSending.type: //0x05
                        guard let ss = self.readStopSendingFrame() else { break readLoop }
                        frames.append(ss)
                    case Frames.Crypto.type: // 0x06
                        guard let crypto = self.readCryptoFrame() else { break readLoop }
                        frames.append(crypto)
                    case Frames.NewToken.type: // 0x07
                        guard let nt = self.readNewTokenFrame() else { break readLoop }
                        frames.append(nt)
                    case 0x08...0x0f: // Stream Frames
                        guard let streamFrame = self.readStreamFrame() else { break readLoop }
                        frames.append(streamFrame)
                    case Frames.MaxData.type: //0x10
                        guard let maxData = self.readMaxDataFrame() else { break readLoop }
                        frames.append(maxData)
                    case Frames.MaxStreamData.type: //0x11
                        guard let maxStreamData = self.readMaxStreamDataFrame() else { break readLoop }
                        frames.append(maxStreamData)
                    case 0x12...0x13: //Max Streams Frame
                        guard let maxStreams = self.readMaxStreamsFrame() else { break readLoop }
                        frames.append(maxStreams)
                    case Frames.DataBlocked.type: //0x14
                        guard let dataBlocked = self.readDataBlockedFrame() else { break readLoop }
                        frames.append(dataBlocked)
                    case Frames.StreamDataBlocked.type: //0x15
                        guard let streamDataBlocked = self.readStreamDataBlockedFrame() else { break readLoop }
                        frames.append(streamDataBlocked)
                    case 0x16...0x17: //StreamsBlocked Frame
                        guard let streamsBlocked = self.readStreamsBlockedFrame() else { break readLoop }
                        frames.append(streamsBlocked)
                    case Frames.NewConnectionID.type: //0x18
                        guard let ncid = self.readNewConnectionIDFrame() else { break readLoop }
                        frames.append(ncid)
                    case Frames.RetireConnectionID.type: //0x19
                        guard let retireID = self.readRetireConnectionIDFrame() else { break readLoop }
                        frames.append(retireID)
                    case Frames.PathChallenge.type: //0x1a
                        guard let pathChallenge = self.readPathChallengeFrame() else { break readLoop }
                        frames.append(pathChallenge)
                    case Frames.PathResponse.type: //0x1b
                        guard let pathResponse = self.readPathResponseFrame() else { break readLoop }
                        frames.append(pathResponse)
                    case 0x1c...0x1d: //ConnectionClose Frame
                        guard let conClose = self.readConnectionCloseFrame() else { break readLoop }
                        frames.append(conClose)
                    case Frames.HandshakeDone.type: // 0x1e
                        guard let hd = self.readHandshakeDoneFrame() else { break readLoop }
                        frames.append(hd)
                    default:
                        print("TODO::Handle Frame Type: \([firstByte].hexString)")
                        leftoverBytes = self.readSlice(length: self.readableBytes)
                        break readLoop
                }
            }
            if self.readableBytes != 0 { return nil }

            return (frames: frames, leftoverBytes: leftoverBytes)
        }

        guard let result else { throw Errors.InvalidFrame }

        return result
    }
}

extension Array where Element == UInt8 {
    internal func parsePayloadIntoFrames() throws -> (frames: [any Frame], leftoverBytes: [UInt8]?) {
        var buf = ByteBuffer(bytes: self)
        let res = try buf.parsePayloadIntoFrames()
        if let leftoverBytes = res.leftoverBytes {
            return (frames: res.frames, leftoverBytes: Array(leftoverBytes.readableBytesView))
        }
        return (frames: res.frames, leftoverBytes: nil)
    }
}