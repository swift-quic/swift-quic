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

import Atomics
import NIOCore

final class StreamStateHandler: ChannelInboundHandler {
    public typealias InboundIn = ByteBuffer
    public typealias OutboundOut = ByteBuffer

    func handlerAdded(context: ChannelHandlerContext) {
        print("StreamStateHandler::Added")
        if let chan = context.channel as? QuicStreamChannel {
            print("Got our StreamID::\(chan.streamID)")
        }
    }

    func handlerRemoved(context: ChannelHandlerContext) {
        print("StreamStateHandler::Removed")
    }

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        print("StreamStateHandler::ChannelRead")
        let buf = self.unwrapInboundIn(data)
        print("StreamStateHandler::Got Message `\(buf.getString(at: buf.readerIndex, length: buf.readableBytes) ?? "")`")
    }

    public func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        print("StreamStateHandler::Write")
    }

    private func sendGoodbye(context: ChannelHandlerContext) {
        print("StreamStateHandler::Sending `Goodbyte`")
        // Lets send "goodbye"
        let promise = context.eventLoop.makePromise(of: Void.self)
        promise.futureResult.whenComplete { result in
            print("StreamStateHandler::Done Writing Goodbyte")
        }
        context.writeAndFlush(
            self.wrapOutboundOut(
                ByteBuffer(string: "Goodbyte")
            ),
            promise: promise
        )
    }
}

final class QuicStreamMultiplexer: ChannelInboundHandler, ChannelOutboundHandler {
    public typealias InboundIn = ByteBuffer
    public typealias InboundOut = ByteBuffer
    public typealias OutboundIn = ByteBuffer
    public typealias OutboundOut = ByteBuffer

    private var streams: [StreamID: QuicStreamChannel] = [:]
    private var inboundStreamStateInitializer: ((Channel) -> EventLoopFuture<Void>)?
    private let channel: Channel
    private var context: ChannelHandlerContext!
    private var didReadChannels: StreamChannelList = StreamChannelList()
    private var flushState: FlushState = .notReading

    public init(channel: Channel, inboundStreamInitializer initializer: ((Channel) -> EventLoopFuture<Void>)?) {
        self.channel = channel
        self.inboundStreamStateInitializer = initializer
    }

    public func handlerAdded(context: ChannelHandlerContext) {
        // We now need to check that we're on the same event loop as the one we were originally given.
        // If we weren't, this is a hard failure, as there is a thread-safety issue here.
        print("QuicStreamMultiplexer::HandlerAdded")
        self.channel.eventLoop.preconditionInEventLoop()
        self.context = context
        if self.channel.isActive {
            print("Attempting to open Stream")
            let messageToSend = "Hello from swift-quic!"
            let newStream = Frames.Stream(streamID: StreamID(rawValue: VarInt(integerLiteral: 0)), offset: VarInt(integerLiteral: 0), length: VarInt(integerLiteral: UInt64(messageToSend.count)), fin: true, data: ByteBuffer(string: messageToSend))
            var buffer = ByteBuffer()
            newStream.encode(into: &buffer)
            self.context.writeAndFlush(self.wrapOutboundOut(buffer), promise: nil)
        }
    }

    public func handlerRemoved(context: ChannelHandlerContext) {
        self.context = nil
    }

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        print("QuicStreamMultiplexer::ChannelRead")
        var buffer = unwrapInboundIn(data)

        guard let frame = buffer.readStreamFrame() else {
            // pass it along the pipeline...
            context.fireChannelRead(self.wrapInboundOut(buffer))
            return
        }

        print("Stream Data \(frame.data.readableBytesView.hexString)")

        self.flushState.startReading()

        // Mux on StreamID
        if let channel = streams[frame.streamID] {
            // Forward the data along
            print("Forwarding data")
            channel.receiveInboundFrame(frame.data)

            if !channel.inList {
                self.didReadChannels.append(channel)
            }
        } else {
            // Open a new stream
            // TODO: Is this a new stream frame?
            print("Opening new Stream for \(frame.streamID)")
            let channel = QuicStreamChannel(allocator: self.channel.allocator, parent: self.channel, multiplexer: self, streamID: frame.streamID)
            self.streams[frame.streamID] = channel

            channel.configure(initializer: self.inboundStreamStateInitializer, userPromise: nil)
            channel.receiveInboundFrame(frame.data)

            if !channel.inList {
                self.didReadChannels.append(channel)
            }
        }
    }

    public func channelReadComplete(context: ChannelHandlerContext) {
        /// Call channelReadComplete on the children until this has been propogated enough.
        while let channel = self.didReadChannels.removeFirst() {
            channel.receiveParentChannelReadComplete()
        }

        if case .flushPending = self.flushState {
            self.flushState = .notReading
            context.flush()
        } else {
            self.flushState = .notReading
        }

        /// propogate the readComplete event along the main channel pipeline
        context.fireChannelReadComplete()
    }

    public func flush(context: ChannelHandlerContext) {
        switch self.flushState {
            case .reading, .flushPending:
                self.flushState = .flushPending
            case .notReading:
                context.flush()
        }
    }

    public func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        /* for now just forward */
        print("TODO: Handle Write!")
        context.write(self.wrapOutboundOut(self.unwrapOutboundIn(data)), promise: promise)
    }

    public func channelActive(context: ChannelHandlerContext) {
        // We just got channelActive. Any previously existing channels may be marked active.
        //self.activateChannels(self.streams.values, context: context)
        //self.activateChannels(self.pendingStreams.values, context: context)

        context.fireChannelActive()
    }

//    private func activateChannels<Channels: Sequence>(_ channels: Channels, context: ChannelHandlerContext) where Channels.Element == UDPStreamChannel {
//        for channel in channels {
//            // We double-check the channel activity here, because it's possible action taken during
//            // the activation of one of the child channels will cause the parent to close!
//            if context.channel.isActive {
//                channel.performActivation()
//            }
//        }
//    }

    public func channelInactive(context: ChannelHandlerContext) {
        for channel in self.streams.values {
            channel.receiveStreamClosed(nil)
        }

        context.fireChannelInactive()
    }
}

extension QuicStreamMultiplexer {
    /// The state of the multiplexer for flush coalescing.
    ///
    /// The stream multiplexer aims to perform limited flush coalescing on the read side by delaying flushes from the child and
    /// parent channels until channelReadComplete is received. To do this we need to track what state we're in.
    enum FlushState {
        /// No channelReads have been fired since the last channelReadComplete, so we probably aren't reading. Let any
        /// flushes through.
        case notReading

        /// We've started reading, but don't have any pending flushes.
        case reading

        /// We're in the read loop, and have received a flush.
        case flushPending

        mutating func startReading() {
            if case .notReading = self {
                self = .reading
            }
        }
    }
}

extension QuicStreamMultiplexer {
    internal func childChannelClosed(id: StreamID) {
        print("QuicStreamMultiplexer: Closing Child Channel Stream with ID: \(id)")
        self.streams.removeValue(forKey: id)
    }

    // TODO: Fixme
    internal func childChannelWrite(_ frame: Frames.Stream, promise: EventLoopPromise<Void>?) {
        print("ChildChannelWrite::FIXME::\(frame.data.readableBytesView.hexString)")
        print(frame)
        var buf = ByteBuffer()
        frame.encode(into: &buf)
        self.context.write(self.wrapOutboundOut(buf), promise: promise)
    }

    internal func childChannelFlush() {
        self.flush(context: self.context)
    }
}

/// The current state of a Connection channel.
private enum StreamChannelState {
    /// The connection has been created, but not configured.
    case idle

    /// The is "active": we haven't sent channelActive yet, but it exists on the network and any shutdown must cause a frame to be emitted.
    case remoteActive

    /// This is also "active", but different to the above: we've sent channelActive, but the NIOHTTP2Handler hasn't seen the frame yet,
    /// and so we can close this channel without action if needed.
    case localActive

    /// This is actually active: channelActive has been fired and the HTTP2Handler believes this stream exists.
    case active

    /// We are closing from a state where channelActive had been fired. In practice this is only ever active, as
    /// in localActive we transition directly to closed.
    case closing

    /// We're closing from a state where we have never fired channel active, but where the channel was on the network.
    /// This means we need to send frames and wait for their side effects.
    case closingNeverActivated

    /// We're fully closed.
    case closed

    mutating func activate() {
        switch self {
            case .idle:
                self = .localActive
            case .remoteActive:
                self = .active
            case .localActive, .active, .closing, .closingNeverActivated, .closed:
                preconditionFailure("Became active from state \(self)")
        }
    }

    mutating func networkActive() {
        switch self {
            case .idle:
                self = .remoteActive
            case .localActive:
                self = .active
            case .closed:
                preconditionFailure("Stream must be reset on network activation when closed")
            case .remoteActive, .active, .closing, .closingNeverActivated:
                preconditionFailure("Cannot become network active twice, in state \(self)")
        }
    }

    mutating func beginClosing() {
        switch self {
            case .active, .closing:
                self = .closing
            case .closingNeverActivated, .remoteActive:
                self = .closingNeverActivated
            case .idle, .localActive:
                preconditionFailure("Idle streams immediately close")
            case .closed:
                preconditionFailure("Cannot begin closing while closed")
        }
    }

    mutating func completeClosing() {
        switch self {
            case .idle, .remoteActive, .closing, .closingNeverActivated, .active, .localActive:
                self = .closed
            case .closed:
                preconditionFailure("Complete closing from \(self)")
        }
    }
}

/// QuicStreamChannel
/// - Note: This is essentially copy-pasted from NIO's HTTP2 Channel
private final class QuicStreamChannel: Channel, ChannelCore {

    public var isWritable: Bool {
        return true
    }

    private var _isActive: Bool {
        return self.state == .active || self.state == .closing || self.state == .localActive
    }

    public var isActive: Bool {
//        return parent!.isActive
        return self._isActiveAtomic.load(ordering: .relaxed)
    }

    private let _isActiveAtomic: ManagedAtomic<Bool>

    public var _channelCore: ChannelCore {
        return self
    }

    var eventLoop: EventLoop

    private var _pipeline: ChannelPipeline!

    public let allocator: ByteBufferAllocator

    private let closePromise: EventLoopPromise<Void>

    /// If close0 was called but the stream could not synchronously close (because it's currently
    /// active), the promise is stored here until it can be fulfilled.
    private var pendingClosePromise: EventLoopPromise<Void>?

    private let parentMultiplexer: QuicStreamMultiplexer

    public var closeFuture: EventLoopFuture<Void> {
        return self.closePromise.futureResult
    }

    public var pipeline: ChannelPipeline {
        return self._pipeline
    }

    public let streamID: StreamID

    public let localAddress: SocketAddress?

    public let remoteAddress: SocketAddress?

    public let parent: Channel?

    private var state: StreamChannelState

    /// Whether a call to `read` has happened without any frames available to read (that is, whether newly
    /// received frames should be immediately delivered to the pipeline).
    private var unsatisfiedRead: Bool = false

    private var pendingReads: CircularBuffer<ByteBuffer> = CircularBuffer(initialCapacity: 8)

    private var pendingWrites: MarkedCircularBuffer<(ByteBuffer, EventLoopPromise<Void>?)> = MarkedCircularBuffer(initialCapacity: 8)

    /// A list node used to hold stream channels.
    internal var streamChannelListNode: StreamChannelListNode = StreamChannelListNode()

    func localAddress0() throws -> SocketAddress {
        fatalError()
    }

    func remoteAddress0() throws -> SocketAddress {
        self.remoteAddress!
        //fatalError()
    }

    internal init(allocator: ByteBufferAllocator,
                  parent: Channel,
                  multiplexer: QuicStreamMultiplexer,
                  streamID: StreamID) {
        self.allocator = allocator
        self.closePromise = parent.eventLoop.makePromise()
        self.streamID = streamID
        self.localAddress = parent.localAddress
        self.remoteAddress = parent.remoteAddress
        self.parent = parent
        self.eventLoop = parent.eventLoop
        self.parentMultiplexer = multiplexer
        //self.windowManager = InboundWindowManager(targetSize: Int32(targetWindowSize))
        self._isActiveAtomic = .init(false)
        //self._isWritable = .makeAtomic(value: true)
        self.state = .idle
        //self.streamDataType = streamDataType
        //self.writabilityManager = StreamChannelFlowController(highWatermark: outboundBytesHighWatermark,
        //                                                      lowWatermark: outboundBytesLowWatermark,
        //                                                      parentIsWritable: parent.isWritable)

        // To begin with we initialize autoRead to false, but we are going to fetch it from our parent before we
        // go much further.
        //self.autoRead = false
        self._pipeline = ChannelPipeline(channel: self)
        print("Quic Stream Channel Initialized (bound to remoteAddress: \(self.remoteAddress?.description ?? "NIL"))")
    }

    func configure(initializer: ((Channel) -> EventLoopFuture<Void>)?, userPromise promise: EventLoopPromise<Channel>?) {
        if let initializer = initializer {
            initializer(self).whenComplete { result in
                switch result {
                    case .success:
                        self.postInitializerActivate(promise: promise)
                    case .failure(let error):
                        self.configurationFailed(withError: error, promise: promise)
                }
            }
        } else {
            self.postInitializerActivate(promise: promise)
        }
    }

    /// Activates the channel if the parent channel is active and succeeds the given `promise`.
    private func postInitializerActivate(promise: EventLoopPromise<Channel>?) {
        // This force unwrap is safe as parent is assigned in the initializer, and never unassigned.
        // If parent is not active, we expect to receive a channelActive later.
        if self.parent!.isActive {
            self.modifyingState { $0.activate() }
            self.pipeline.fireChannelActive()
            self.tryToAutoRead()
            self.deliverPendingWrites()
        }

        // We aren't using cascade here to avoid the allocations it causes.
        promise?.succeed(self)
    }

    private func configurationFailed(withError error: Error, promise: EventLoopPromise<Channel>?) {
        switch self.state {
            case .idle, .localActive, .closed:
                // The stream isn't open on the network, nothing to close.
                self.errorEncountered(error: error)
            case .remoteActive, .active, .closing, .closingNeverActivated:
                // In all of these states the stream is still on the network and we may need to take action.
                self.closedWhileOpen()
        }

        promise?.fail(error)
    }

    func setOption<Option: ChannelOption>(_ option: Option, value: Option.Value) -> EventLoopFuture<Void> {
        if self.eventLoop.inEventLoop {
            do {
                return self.eventLoop.makeSucceededFuture(try self.setOption0(option, value: value))
            } catch {
                return self.eventLoop.makeFailedFuture(error)
            }
        } else {
            return self.eventLoop.submit { try self.setOption0(option, value: value) }
        }
    }

    public func getOption<Option: ChannelOption>(_ option: Option) -> EventLoopFuture<Option.Value> {
        if self.eventLoop.inEventLoop {
            do {
                return self.eventLoop.makeSucceededFuture(try self.getOption0(option))
            } catch {
                return self.eventLoop.makeFailedFuture(error)
            }
        } else {
            return self.eventLoop.submit { try self.getOption0(option) }
        }
    }

    private func setOption0<Option: ChannelOption>(_ option: Option, value: Option.Value) throws {
        self.eventLoop.preconditionInEventLoop()

        switch option {
            default:
                fatalError("setting option \(option) on QuicConnectionChannel not supported")
        }
    }

    private func getOption0<Option: ChannelOption>(_ option: Option) throws -> Option.Value {
        self.eventLoop.preconditionInEventLoop()

        switch option {
            case is ChannelOptions.Types.AutoReadOption:
                return ChannelOptions.Types.AutoReadOption.Value(false) as! Option.Value
            default:
                fatalError("option \(option) not supported on QuicConnectionChannel")
        }
    }

    public func register0(promise: EventLoopPromise<Void>?) {
        fatalError("not implemented \(#function)")
    }

    public func bind0(to: SocketAddress, promise: EventLoopPromise<Void>?) {
        fatalError("not implemented \(#function)")
    }

    public func connect0(to: SocketAddress, promise: EventLoopPromise<Void>?) {
        fatalError("not implemented \(#function)")
    }

    public func write0(_ data: NIOAny, promise: EventLoopPromise<Void>?) {
        guard self.state != .closed else {
            promise?.fail(ChannelError.ioOnClosedChannel)
            return
        }

        let streamData: ByteBuffer = self.unwrapData(data)
        //let streamData: HTTP2StreamData
        //switch self.streamDataType {
        //case .frame:
        //    streamData = .frame(self.unwrapData(data))
        //case .framePayload:
        //    streamData = .framePayload(self.unwrapData(data))
        //}

        // We need a promise to attach our flow control callback to.
        // Regardless of whether the write succeeded or failed, we don't count
        // the bytes any longer.
        let promise = promise ?? self.eventLoop.makePromise()
        //let writeSize = streamData.estimatedFrameSize

        // Right now we deal with this math by just attaching a callback to all promises. This is going
        // to be annoyingly expensive, but for now it's the most straightforward approach.
//        promise.futureResult.hop(to: self.eventLoop).whenComplete { (_: Result<Void, Error>) in
//            if case .changed(newValue: let value) = self.writabilityManager.wroteBytes(writeSize) {
//                self.changeWritability(to: value)
//            }
//        }
        self.pendingWrites.append((streamData, promise))

        // Ok, we can make an outcall now, which means we can safely deal with the flow control.
//        if case .changed(newValue: let value) = self.writabilityManager.bufferedBytes(writeSize) {
//            self.changeWritability(to: value)
//        }
    }

    public func flush0() {
        self.pendingWrites.mark()

        if self._isActive {
            self.deliverPendingWrites()
        }
    }

    public func read0() {
        if self.unsatisfiedRead {
            // We already have an unsatisfied read, let's do nothing.
            return
        }

        // At this stage, we have an unsatisfied read. If there is no pending data to read,
        // we're going to call read() on the parent channel. Otherwise, we're going to
        // succeed the read out of our pending data.
        self.unsatisfiedRead = true
        if !self.pendingReads.isEmpty {
            self.tryToRead()
        } else {
            self.parent?.read()
        }
    }

    public func close0(error: Error, mode: CloseMode, promise: EventLoopPromise<Void>?) {
        // If the stream is already closed, we can fail this early and abort processing. If it's not, we need to emit a
        // RST_STREAM frame.
        guard self.state != .closed else {
            promise?.fail(ChannelError.alreadyClosed)
            return
        }

        // Store the pending close promise: it'll be succeeded later.
        if let promise = promise {
            if let pendingPromise = self.pendingClosePromise {
                pendingPromise.futureResult.cascade(to: promise)
            } else {
                self.pendingClosePromise = promise
            }
        }

        switch self.state {
            case .idle, .localActive, .closed:
                // The stream isn't open on the network, just go straight to closed cleanly.
                self.closedCleanly()
            case .remoteActive, .active, .closing, .closingNeverActivated:
                // In all of these states the stream is still on the network and we need to wait.
                self.closedWhileOpen()
        }
    }

    func triggerUserOutboundEvent0(_ event: Any, promise: EventLoopPromise<Void>?) {
        // do nothing
    }

    func channelRead0(_ data: NIOAny) {
        // do nothing
    }

    func errorCaught0(error: Error) {
        // do nothing
    }

    /// Called when the channel was closed from the pipeline while the stream is still open.
    ///
    /// Will emit a RST_STREAM frame in order to close the stream. Note that this function does not
    /// directly close the stream: it waits until the stream closed notification is fired.
    private func closedWhileOpen() {
        precondition(self.state != .closed)
        guard self.state != .closing else {
            // If we're already closing, nothing to do here.
            return
        }

        self.modifyingState { $0.beginClosing() }

        // Send a close message/frame here if necessary
        self.parentMultiplexer.childChannelFlush()
    }

    private func closedCleanly() {
        guard self.state != .closed else {
            return
        }
        self.modifyingState { $0.completeClosing() }
        self.dropPendingReads()
        self.failPendingWrites(error: ChannelError.eof)
        if let promise = self.pendingClosePromise {
            self.pendingClosePromise = nil
            promise.succeed(())
        }
        self.pipeline.fireChannelInactive()

        self.eventLoop.execute {
            self.removeHandlers(pipeline: self.pipeline)
            self.closePromise.succeed(())

            self.parentMultiplexer.childChannelClosed(id: self.streamID)
        }
    }

    fileprivate func errorEncountered(error: Error) {
        guard self.state != .closed else {
            return
        }
        self.modifyingState { $0.completeClosing() }
        self.dropPendingReads()
        self.failPendingWrites(error: error)
        if let promise = self.pendingClosePromise {
            self.pendingClosePromise = nil
            promise.fail(error)
        }
        self.pipeline.fireErrorCaught(error)
        self.pipeline.fireChannelInactive()

        self.eventLoop.execute {
            self.removeHandlers(pipeline: self.pipeline)
            self.closePromise.fail(error)
            self.parentMultiplexer.childChannelClosed(id: self.streamID)
        }
    }

    private func tryToRead() {
        // If there's no read to satisfy, no worries about it.
        guard self.unsatisfiedRead else {
            return
        }

        // If we're not active, we will hold on to these reads.
        guard self._isActive else {
            return
        }

        // If there are no pending reads, do nothing.
        guard !self.pendingReads.isEmpty else {
            return
        }

        // Ok, we're satisfying a read here.
        self.unsatisfiedRead = false
        self.deliverPendingReads()
        self.tryToAutoRead()
    }

    private func changeWritability(to newWritability: Bool) {
        //self._isWritable.store(newWritability)
        self.pipeline.fireChannelWritabilityChanged()
    }

    private func tryToAutoRead() {
        self.pipeline.read()
        //if self.autoRead {
        //    // If auto-read is turned on, recurse into channelPipeline.read().
        //    // This cannot recurse indefinitely unless frames are being delivered
        //    // by the read stacks, which is generally fairly unlikely to continue unbounded.
        //    self.pipeline.read()
        //}
    }
}

// MARK: - Functions used to manage pending reads and writes.

private extension QuicStreamChannel {
    /// Drop all pending reads.
    private func dropPendingReads() {
        /// We don't need to report the dropped reads, just remove them all.
        self.pendingReads.removeAll()
    }

    /// Deliver all pending reads to the channel.
    private func deliverPendingReads() {
        assert(self._isActive)
        while !self.pendingReads.isEmpty {
            let frame = self.pendingReads.removeFirst()

            let anyStreamData = NIOAny(frame)
            //let dataLength: Int?

//            switch self.streamDataType {
//            case .frame:
//                anyStreamData = NIOAny(frame)
//            case .framePayload:
//                anyStreamData = NIOAny(frame.payload)
//            }

//            switch frame.payload {
//            case .data(let data):
//                dataLength = data.data.readableBytes
//            default:
//                dataLength = nil
//            }

            self.pipeline.fireChannelRead(anyStreamData)

            //if let size = dataLength, let increment = self.windowManager.bufferedFrameEmitted(size: size) {
            //    // To have a pending read, we must have a stream ID.
            //    let frame = HTTP2Frame(streamID: self.streamID!, payload: .windowUpdate(windowSizeIncrement: increment))
            //    self.receiveOutboundFrame(frame, promise: nil)
            //    // This flush should really go away, but we need it for now until we sort out window management.
            //    self.multiplexer.childChannelFlush()
            //}
        }
        self.pipeline.fireChannelReadComplete()
    }

    /// Delivers all pending flushed writes to the parent channel.
    private func deliverPendingWrites() {
        // If there are no pending writes, don't bother with the processing.
        guard self.pendingWrites.hasMark else {
            return
        }

        while self.pendingWrites.hasMark {
            let (streamData, promise) = self.pendingWrites.removeFirst()
            let frame = Frames.Stream(streamID: self.streamID, offset: nil, length: nil, fin: false, data: streamData)

            self.receiveOutboundFrame(frame, promise: promise)
        }
        self.parentMultiplexer.childChannelFlush()
    }

    /// Fails all pending writes with the given error.
    private func failPendingWrites(error: Error) {
        assert(self.state == .closed)
        while !self.pendingWrites.isEmpty {
            self.pendingWrites.removeFirst().1?.fail(error)
        }
    }
}

extension QuicStreamChannel {
    // A helper function used to ensure that state modification leads to changes in the channel active atomic.
    private func modifyingState<ReturnType>(_ closure: (inout StreamChannelState) throws -> ReturnType) rethrows -> ReturnType {
        defer {
            self._isActiveAtomic.store(self._isActive, ordering: .relaxed)
        }
        return try closure(&self.state)
    }
}

// MARK: Custom String Convertible

extension QuicStreamChannel {
    public var description: String {
        return "QUICStreamChannel(address: \(String(describing: self.remoteAddress)), isActive: \(self.isActive), isWritable: \(self.isWritable))"
    }
}

// MARK: - Functions used to communicate between the `UDPStreamMultiplexer` and the `UDPStreamChannel`.

private extension QuicStreamChannel {
    /// Called when a frame is received from the network.
    ///
    /// - parameters:
    ///     - frame: The `QuicStreamFrame` received from the network.
    func receiveInboundFrame(_ frame: ByteBuffer) {
        guard self.state != .closed else {
            // Do nothing
            return
        }

        self.pendingReads.append(frame)
    }

    /// Called when a frame is sent to the network.
    ///
    /// - parameters:
    ///     - frame: The `QuicStreamFrame` to send to the network.
    ///     - promise: The promise associated with the frame write.
    private func receiveOutboundFrame(_ frame: Frames.Stream, promise: EventLoopPromise<Void>?) {
        guard self.state != .closed else {
            let error = ChannelError.alreadyClosed
            promise?.fail(error)
            self.errorEncountered(error: error)
            return
        }
        // Send it to the multiplexer
        self.parentMultiplexer.childChannelWrite(frame, promise: promise)
    }

    /// Called when a stream closure is received from the network.
    ///
    /// - parameters:
    ///     - reason: The reason received from the network, if any.
    func receiveStreamClosed(_ reason: Error?) {
        // Avoid emitting any WINDOW_UPDATE frames now that we're closed.
        //self.windowManager.closed = true

        // The stream is closed, we should aim to deliver any read frames we have for it.
        self.tryToRead()

        if let reason = reason {
            self.errorEncountered(error: reason)
        } else {
            self.closedCleanly()
        }
    }

    func receiveParentChannelReadComplete() {
        self.tryToRead()
    }

    func parentChannelWritabilityChanged(newValue: Bool) {
        // There's a trick here that's worth noting: if the child channel hasn't either sent a frame
        // or been activated on the network, we don't actually want to change the observable writability.
        // This is because in this case we really want user code to send a frame as soon as possible to avoid
        // issues with their stream ID becoming out of date. Once the state transitions we can update
        // the writability if needed.
//        guard case .changed(newValue: let localValue) = self.writabilityManager.parentWritabilityChanged(newValue) else {
//            return
//        }

        // Ok, the writability changed.
        switch self.state {
            case .idle, .localActive:
                // Do nothing here.
                return
            case .remoteActive, .active, .closing, .closingNeverActivated, .closed:
                //self._isWritable.store(localValue)
                self.pipeline.fireChannelWritabilityChanged()
        }
    }
}

/// A linked list for storing MultiplexerAbstractChannels.
///
/// Note that while this object *could* conform to `Sequence`, there is minimal value in doing
/// that here, as it's so single-use. If we find ourselves needing to expand on this data type
/// in future we can revisit that idea.
struct StreamChannelList {
    private var head: QuicStreamChannel?
    private var tail: QuicStreamChannel?
}

/// A node for objects stored in an intrusive linked list.
///
/// Any object that wishes to be stored in a linked list must embed one of these nodes.
struct StreamChannelListNode {
    fileprivate enum ListState {
        case inList(next: QuicStreamChannel?)
        case notInList
    }

    fileprivate var state: ListState = .notInList

    internal init() { }
}

private extension StreamChannelList {
    /// Append an element to the linked list.
    mutating func append(_ element: QuicStreamChannel) {
        precondition(!element.inList)

        guard case .notInList = element.streamChannelListNode.state else {
            preconditionFailure("Appended an element already in a list")
        }

        element.streamChannelListNode.state = .inList(next: nil)

        if let tail = self.tail {
            tail.streamChannelListNode.state = .inList(next: element)
            self.tail = element
        } else {
            assert(self.head == nil)
            self.head = element
            self.tail = element
        }
    }

    mutating func removeFirst() -> QuicStreamChannel? {
        guard let head = self.head else {
            assert(self.tail == nil)
            return nil
        }

        guard case .inList(let next) = head.streamChannelListNode.state else {
            preconditionFailure("Popped an element not in a list")
        }

        self.head = next
        if self.head == nil {
            assert(self.tail == head)
            self.tail = nil
        }

        head.streamChannelListNode = .init()
        return head
    }

    mutating func removeAll() {
        while self.removeFirst() != nil { }
    }
}

// MARK: - IntrusiveLinkedListElement helpers.

extension QuicStreamChannel {
    /// Whether this element is currently in a list.
    internal var inList: Bool {
        switch self.streamChannelListNode.state {
            case .inList:
                return true
            case .notInList:
                return false
        }
    }
}

extension QuicStreamChannel: Equatable {
    static func == (lhs: QuicStreamChannel, rhs: QuicStreamChannel) -> Bool {
        return lhs === rhs
    }
}

extension QuicStreamChannel: Hashable {
    func hash(into hasher: inout Hasher) {
        hasher.combine(ObjectIdentifier(self))
    }
}
