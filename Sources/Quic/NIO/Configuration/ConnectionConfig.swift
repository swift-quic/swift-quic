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
import NIOSSL

/// - Note: Borrowed from Quiche!!

protocol CongestionControlAlgorithm { }

// TODO: Implement me!
struct CubicCongestionControlAlgo: CongestionControlAlgorithm { }

/// Stores configuration shared between multiple connections.
struct Config {
    public private(set) var localTransportParams: TransportParams

    public private(set) var version: Version

    public private(set) var tlsContex: NIOSSLContext

    public private(set) var applicationProtos: [[UInt8]]

    public private(set) var grease: Bool

    public private(set) var congestionControlAlgorithm: CongestionControlAlgorithm

    public private(set) var hystart: Bool

    public private(set) var pacing: Bool

    public private(set) var dgramRecvMaxQueueLength: UInt64
    public private(set) var dgramSendMaxQueueLength: UInt64

    public private(set) var maxSendUDPPayloadSize: UInt64

    public private(set) var maxConnectionWindow: UInt64
    public private(set) var maxStreamWindow: UInt64

    public private(set) var disableDCIDReuse: Bool

    init(version: Version) throws {
        try self.init(version: version, withTLSContext: NIOSSLContext(configuration: TLSConfiguration.makeClientConfiguration()))
    }

    init(version: Quic.Version, withTLSContext tlsContext: NIOSSLContext) throws {
        guard isReserved(version: version) == false, isSupported(version: version) else { throw Errors.UnsupportedVersion }
        self.version = version
        self.tlsContex = tlsContext
        self.localTransportParams = TransportParams.default
        self.applicationProtos = []
        self.grease = false // true
        self.congestionControlAlgorithm = CubicCongestionControlAlgo()
        self.hystart = false // true
        self.pacing = false // true
        self.dgramRecvMaxQueueLength = ConnectionParams.DEFAULT_MAX_DGRAM_QUEUE_LEN
        self.dgramSendMaxQueueLength = ConnectionParams.DEFAULT_MAX_DGRAM_QUEUE_LEN
        self.maxSendUDPPayloadSize = ConnectionParams.MAX_SEND_UDP_PAYLOAD_SIZE
        self.maxConnectionWindow = ConnectionParams.MAX_CONNECTION_WINDOW
        self.maxStreamWindow = StreamParams.MAX_STREAM_WINDOW
        self.disableDCIDReuse = true // false
    }
}

extension Config {
    /// Configures the given certificate chain.
    ///
    /// The content of `file` is parsed as a PEM-encoded leaf certificate,
    /// followed by optional intermediate certificates.
    ///
    /// ## Examples:
    ///
    /// ```no_run
    /// # let mut config = quiche::Config::new(0xbabababa)?;
    /// config.load_cert_chain_from_pem_file("/path/to/cert.pem")?;
    /// # Ok::<(), quiche::Error>(())
    /// ```
    public mutating func loadCertChainFromPEMFile(file: String) -> EventLoopPromise<Bool> {
        //NIOSSLContext.useCertificateChainFile(file, context: &self.tlsContex)
        preconditionFailure("Not Yet Implemented")
    }

    /// Configures the given private key.
    ///
    /// The content of `file` is parsed as a PEM-encoded private key.
    ///
    /// ## Examples:
    ///
    /// ```no_run
    /// # let mut config = quiche::Config::new(0xbabababa)?;
    /// config.load_priv_key_from_pem_file("/path/to/key.pem")?;
    /// # Ok::<(), quiche::Error>(())
    /// ```
    public mutating func loadPrivateKeyFromPEMFile(file: String) -> EventLoopPromise<Bool> {
        //self.tls_ctx.use_privkey_file(file)
        preconditionFailure("Not Yet Implemented")
    }

    /// Specifies a file where trusted CA certificates are stored for the
    /// purposes of certificate verification.
    ///
    /// The content of `file` is parsed as a PEM-encoded certificate chain.
    ///
    /// ## Examples:
    ///
    /// ```no_run
    /// # let mut config = quiche::Config::new(0xbabababa)?;
    /// config.load_verify_locations_from_file("/path/to/cert.pem")?;
    /// # Ok::<(), quiche::Error>(())
    /// ```
    public mutating func loadVerifyLocationsFromFile(file: String) -> EventLoopPromise<Bool> {
        //self.tls_ctx.load_verify_locations_from_file(file)
        preconditionFailure("Not Yet Implemented")
    }

    /// Specifies a directory where trusted CA certificates are stored for the
    /// purposes of certificate verification.
    ///
    /// The content of `dir` a set of PEM-encoded certificate chains.
    ///
    /// ## Examples:
    ///
    /// ```no_run
    /// # let mut config = quiche::Config::new(0xbabababa)?;
    /// config.load_verify_locations_from_directory("/path/to/certs")?;
    /// # Ok::<(), quiche::Error>(())
    /// ```
    public mutating func loadVerifyLocationsFromDirectory(dir: String) -> EventLoopPromise<Bool> {
        //self.tls_ctx.load_verify_locations_from_directory(dir)
        preconditionFailure("Not Yet Implemented")
    }

    /// Configures whether to verify the peer's certificate.
    ///
    /// The default value is `true` for client connections, and `false` for
    /// server ones.
    public mutating func verifyPeer(verify: Bool) {
        //self.tls_ctx.set_verify(verify);
        preconditionFailure("Not Yet Implemented")
    }

    /// Configures whether to send GREASE values.
    ///
    /// The default value is `true`.
    public mutating func grease(grease: Bool) {
        self.grease = grease
    }

    /// Enables logging of secrets.
    ///
    /// When logging is enabled, the [`set_keylog()`] method must be called on
    /// the connection for its cryptographic secrets to be logged in the
    /// [keylog] format to the specified writer.
    ///
    /// [`set_keylog()`]: struct.Connection.html#method.set_keylog
    /// [keylog]: https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format
    public mutating func log_keys() {
        //self.tls_ctx.enable_keylog();
        //NIOSSLContext.keyLogCallback = ...
        preconditionFailure("Not Yet Implemented")
    }

    /// Configures the session ticket key material.
    ///
    /// On the server this key will be used to encrypt and decrypt session
    /// tickets, used to perform session resumption without server-side state.
    ///
    /// By default a key is generated internally, and rotated regularly, so
    /// applications don't need to call this unless they need to use a
    /// specific key (e.g. in order to support resumption across multiple
    /// servers), in which case the application is also responsible for
    /// rotating the key to provide forward secrecy.
    public mutating func set_ticket_key(key: [UInt8]) -> EventLoopPromise<Bool> {
        //self.tls_ctx.set_ticket_key(key)
        //NIOSSLContext.set_ticket_key(key: key)
        preconditionFailure("Not Yet Implemented")
    }

    /// Enables sending or receiving early data.
    public mutating func enableEarlyData() {
        //self.tls_ctx.set_early_data_enabled(true);
        //NIOSSLContext.set_enable_early_data(true)
        preconditionFailure("Not Yet Implemented")
    }

    /// Configures the list of supported application protocols.
    ///
    /// On the client this configures the list of protocols to send to the
    /// server as part of the ALPN extension.
    ///
    /// On the server this configures the list of supported protocols to match
    /// against the client-supplied list.
    ///
    /// Applications must set a value, but no default is provided.
    ///
    /// ## Examples:
    ///
    /// ```
    /// # let mut config = quiche::Config::new(0xbabababa)?;
    /// config.set_application_protos(&[b"http/1.1", b"http/0.9"]);
    /// # Ok::<(), quiche::Error>(())
    /// ```
    public mutating func setApplicationProtos(list: [[UInt8]]) -> EventLoopPromise<Bool> {
        self.applicationProtos = list
        //NIOSSLContext.setAlpnProtocols(list, context: self.tlsContex)
        preconditionFailure("Not Yet Implemented")
    }

    /// Configures the list of supported application protocols using wire
    /// format.
    ///
    /// The list of protocols `protos` must be a series of non-empty, 8-bit
    /// length-prefixed strings.
    ///
    /// See [`set_application_protos`](Self::set_application_protos) for more
    /// background about application protocols.
    ///
    /// ## Examples:
    ///
    /// ```
    /// # let mut config = quiche::Config::new(0xbabababa)?;
    /// config.set_application_protos_wire_format(b"\x08http/1.1\x08http/0.9")?;
    /// # Ok::<(), quiche::Error>(())
    /// ```
    public mutating func setApplicationProtosWireFormat(protos: inout ByteBuffer) -> EventLoopPromise<Bool> {
        var protoList: [[UInt8]] = []

        while let proto = protos.readQuicVarIntLengthPrefixedBytes() {
            protoList.append(proto)
        }

        return self.setApplicationProtos(list: protoList)
    }

    /// Sets the `max_idle_timeout` transport parameter, in milliseconds.
    ///
    /// The default value is infinite, that is, no timeout is used.
    public mutating func setMaxIdleTimeout(_ v: UInt64) {
        self.localTransportParams.max_idle_timeout = v
    }

    /// Sets the `max_udp_payload_size transport` parameter.
    ///
    /// The default value is `65527`.
    public mutating func setMaxRecvUDPPayloadSize(_ v: UInt) {
        self.localTransportParams.max_udp_payload_size = UInt64(v)
    }

    /// Sets the maximum outgoing UDP payload size.
    ///
    /// The default and minimum value is `1200`.
    public mutating func setMaxSendUDPPayloadSize(_ v: UInt64) {
        self.maxSendUDPPayloadSize = max(v, ConnectionParams.MAX_SEND_UDP_PAYLOAD_SIZE)
    }

    /// Sets the `initial_max_data` transport parameter.
    ///
    /// When set to a non-zero value quiche will only allow at most `v` bytes
    /// of incoming stream data to be buffered for the whole connection (that
    /// is, data that is not yet read by the application) and will allow more
    /// data to be received as the buffer is consumed by the application.
    ///
    /// The default value is `0`.
    public mutating func setInitialMaxData(_ v: UInt64) {
        self.localTransportParams.initial_max_data = v
    }

    /// Sets the `initial_max_stream_data_bidi_local` transport parameter.
    ///
    /// When set to a non-zero value quiche will only allow at most `v` bytes
    /// of incoming stream data to be buffered for each locally-initiated
    /// bidirectional stream (that is, data that is not yet read by the
    /// application) and will allow more data to be received as the buffer is
    /// consumed by the application.
    ///
    /// The default value is `0`.
    public mutating func setInitialMaxStreamDataBidiLocal(_ v: UInt64) {
        self.localTransportParams.initial_max_stream_data_bidi_local = v
    }

    /// Sets the `initial_max_stream_data_bidi_remote` transport parameter.
    ///
    /// When set to a non-zero value quiche will only allow at most `v` bytes
    /// of incoming stream data to be buffered for each remotely-initiated
    /// bidirectional stream (that is, data that is not yet read by the
    /// application) and will allow more data to be received as the buffer is
    /// consumed by the application.
    ///
    /// The default value is `0`.
    public mutating func setInitialMaxStreamDataBidiRemote(_ v: UInt64) {
        self.localTransportParams.initial_max_stream_data_bidi_remote = v
    }

    /// Sets the `initial_max_stream_data_uni` transport parameter.
    ///
    /// When set to a non-zero value quiche will only allow at most `v` bytes
    /// of incoming stream data to be buffered for each unidirectional stream
    /// (that is, data that is not yet read by the application) and will allow
    /// more data to be received as the buffer is consumed by the application.
    ///
    /// The default value is `0`.
    public mutating func setInitialMaxStreamDataUni(_ v: UInt64) {
        self.localTransportParams.initial_max_stream_data_uni = v
    }

    /// Sets the `initial_max_streams_bidi` transport parameter.
    ///
    /// When set to a non-zero value quiche will only allow `v` number of
    /// concurrent remotely-initiated bidirectional streams to be open at any
    /// given time and will increase the limit automatically as streams are
    /// completed.
    ///
    /// A bidirectional stream is considered completed when all incoming data
    /// has been read by the application (up to the `fin` offset) or the
    /// stream's read direction has been shutdown, and all outgoing data has
    /// been acked by the peer (up to the `fin` offset) or the stream's write
    /// direction has been shutdown.
    ///
    /// The default value is `0`.
    public mutating func setInitialMaxStreamsBidi(_ v: UInt64) {
        self.localTransportParams.initial_max_streams_bidi = v
    }

    /// Sets the `initial_max_streams_uni` transport parameter.
    ///
    /// When set to a non-zero value quiche will only allow `v` number of
    /// concurrent remotely-initiated unidirectional streams to be open at any
    /// given time and will increase the limit automatically as streams are
    /// completed.
    ///
    /// A unidirectional stream is considered completed when all incoming data
    /// has been read by the application (up to the `fin` offset) or the
    /// stream's read direction has been shutdown.
    ///
    /// The default value is `0`.
    public mutating func setInitialMaxStreamsUni(_ v: UInt64) {
        self.localTransportParams.initial_max_streams_uni = v
    }

    /// Sets the `ack_delay_exponent` transport parameter.
    ///
    /// The default value is `3`.
    public mutating func setAckDelayExponent(_ v: UInt64) {
        self.localTransportParams.ack_delay_exponent = v
    }

    /// Sets the `max_ack_delay` transport parameter.
    ///
    /// The default value is `25`.
    public mutating func setMaxAckDelay(_ v: UInt64) {
        self.localTransportParams.max_ack_delay = v
    }

    /// Sets the `active_connection_id_limit` transport parameter.
    ///
    /// The default value is `2`. Lower values will be ignored.
    public mutating func setActiveConnectionIdLimit(_ v: UInt64) {
        if v >= 2 {
            self.localTransportParams.active_conn_id_limit = v
        }
    }

    /// Sets the `disable_active_migration` transport parameter.
    ///
    /// The default value is `false`.
    public mutating func setDisableActiveMigration(_ v: Bool) {
        self.localTransportParams.disable_active_migration = v
    }

    /// Sets the congestion control algorithm used by string.
    ///
    /// The default value is `cubic`. On error `Error::CongestionControl`
    /// will be returned.
    ///
    /// ## Examples:
    ///
    /// ```
    /// # let mut config = quiche::Config::new(0xbabababa)?;
    /// config.set_cc_algorithm_name("reno");
    /// # Ok::<(), quiche::Error>(())
    /// ```
    public mutating func setCongestionControlAlgorithmName(name: String) -> EventLoopPromise<Bool> {
        //self.cc_algorithm = CongestionControlAlgorithm::from_str(name)?;

        //Ok(())
        //return
        preconditionFailure("Not Yet Implemented")
    }

    /// Sets the congestion control algorithm used.
    ///
    /// The default value is `CongestionControlAlgorithm::CUBIC`.
    public mutating func setCongestionControlAlgorithm(_ algo: CongestionControlAlgorithm) {
        self.congestionControlAlgorithm = algo
    }

    /// Configures whether to enable HyStart++.
    ///
    /// The default value is `true`.
    public mutating func enableHyStart(_ v: Bool) {
        self.hystart = v
    }

    /// Configures whether to enable pacing.
    ///
    /// The default value is `true`.
    public mutating func enablePacing(_ v: Bool) {
        self.pacing = v
    }

    /// Configures whether to enable receiving DATAGRAM frames.
    ///
    /// When enabled, the `max_datagram_frame_size` transport parameter is set
    /// to 65536 as recommended by draft-ietf-quic-datagram-01.
    ///
    /// The default is `false`.
    public mutating func enableDgram(enabled: Bool, recvQueueLength: UInt64, sendQueueLength: UInt64) {
        self.localTransportParams.max_datagram_frame_size = enabled ? ConnectionParams.MAX_DGRAM_FRAME_SIZE : nil
        self.dgramRecvMaxQueueLength = recvQueueLength
        self.dgramSendMaxQueueLength = sendQueueLength
    }

    /// Sets the maximum size of the connection window.
    ///
    /// The default value is MAX_CONNECTION_WINDOW (24MBytes).
    public mutating func setMaxConnectionWindow(_ v: UInt64) {
        self.maxConnectionWindow = v
    }

    /// Sets the maximum size of the stream window.
    ///
    /// The default value is MAX_STREAM_WINDOW (16MBytes).
    public mutating func setMaxStreamWindow(_ v: UInt64) {
        self.maxStreamWindow = v
    }

    /// Sets the initial stateless reset token.
    ///
    /// This value is only advertised by servers. Setting a stateless retry
    /// token as a client has no effect on the connection.
    ///
    /// The default value is `None`.
    public mutating func setStatelessResetToken(token: [UInt8]?) {
        self.localTransportParams.stateless_reset_token = token
    }

    /// Sets whether the QUIC connection should avoid reusing DCIDs over
    /// different paths.
    ///
    /// When set to `true`, it ensures that a destination Connection ID is never
    /// reused on different paths. Such behaviour may lead to connection stall
    /// if the peer performs a non-voluntary migration (e.g., NAT rebinding) and
    /// does not provide additional destination Connection IDs to handle such
    /// event.
    ///
    /// The default value is `false`.
    public mutating func setDisableDCIDReuse(_ v: Bool) {
        self.disableDCIDReuse = v
    }
}
