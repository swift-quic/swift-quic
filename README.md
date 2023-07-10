# SwiftQuic
SwiftQuic is an open-source [Swift] implementation of the [QUIC] protocol.

[![Swift](https://github.com/swift-quic/swift-quic/actions/workflows/swift.yml/badge.svg)](https://github.com/swift-quic/swift-quic/actions/workflows/swift.yml)
[![](https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2Fswift-quic%2Fswift-quic%2Fbadge%3Ftype%3Dswift-versions)](https://swiftpackageindex.com/swift-quic/swift-quic)
[![](https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2Fswift-quic%2Fswift-quic%2Fbadge%3Ftype%3Dplatforms)](https://swiftpackageindex.com/swift-quic/swift-quic)

> ⚠️  This implementation is under heavy development and is not ready for production!

### Current Progress
- [x] Complete a standard handshake using TLS 1.3
- [x] Open a stream and echo data
> Note: The above can be done between either...
>    - A [Swift Server and Client](https://github.com/swift-quic/swift-quic/tree/develop/Tests/QuicTests/NIOTests/HandshakeTests.swift) or
>    - Between Swift and Go (using the [Go Quic](https://github.com/quic-go/quic-go) library)
>        - Check out the [GoInteropTests](https://github.com/swift-quic/swift-quic/tree/develop/Tests/QuicTests/NIOTests/GoInteropTests) for more info.

### How It Works
- All of the Crypto stuff is mostly contained within the [Crypto](https://github.com/swift-quic/swift-quic/tree/develop/Sources/Quic/Crypto) folder and the [`PacketProtectorHandler`](https://github.com/swift-quic/swift-quic/blob/develop/Sources/Quic/NIO/Connection/Handlers/PacketProtectorHandler.swift)
- The NIO Pipeline configuration is discussed [here](https://github.com/swift-quic/swift-quic/discussions/6)
- The TLS Handshake uses a slightly modified version of `swift-nio-ssl` available [here](https://github.com/btoms20/swift-nio-ssl)
- The main connection logic is handled in the [ConnectionStateMachine](https://github.com/swift-quic/swift-quic/blob/develop/Sources/Quic/NIO/Connection/ConnectionStateMachine/ConnectionStateMachine.swift) triggered via `read` and `write` invocations on the [StateHandler](https://github.com/swift-quic/swift-quic/blob/develop/Sources/Quic/NIO/Connection/Handlers/StateHandler.swift).

### Alpha (a working prototype) TODO's
- [ ] Streams & Stream States - [RFC 9000 - Sec 3](https://datatracker.ietf.org/doc/html/rfc9000#section-3)
- [ ] Basic Flow Control - [RFC 9000 - Sec 4](https://datatracker.ietf.org/doc/html/rfc9000#section-4) (max data, max streams, etc)
- [ ] Connections - [RFC 9000 - Sec 5](https://datatracker.ietf.org/doc/html/rfc9000#section-5)
    - [ ] ConnectionID - [RFC 9000 - Sec 5.1](https://datatracker.ietf.org/doc/html/rfc9000#section-5.1)
        - [ ] Generation & Issuance
        - [ ] Retirement
    - [ ] Muxing
    - [ ] Operations
- [ ] Version Negotiation - [RFC 9000 - Sec 6](https://datatracker.ietf.org/doc/html/rfc9000#section-6)
    - [ ] client (consume and switch versions when possible)
    - [ ] server (send Version Negotiation packets)
    - [ ] reserved
- [ ] Handshake - [RFC 9000 - Sec 7](https://datatracker.ietf.org/doc/html/rfc9000#section-7)
    - [x] General Handshake Flow
    - [ ] Negotiating & Authenticating ConnectionIDs
    - [ ] 0RTT Data
    - [ ] Cryptographic Message Buffering 
    - [ ] Key Updates 
        - [ ] Respond to
        - [ ] Initiate
- [ ] Address Validation - [RFC 9000 - Sec 8](https://datatracker.ietf.org/doc/html/rfc9000#section-8)
    - [ ] Address Validation
    - [ ] Path Validation
- [ ] Connection Migration - [RFC 9000 - Sec 9](https://datatracker.ietf.org/doc/html/rfc9000#section-9)
- [ ] Connection Termination - [RFC 9000 - Sec 10](https://datatracker.ietf.org/doc/html/rfc9000#section-10)
    - [ ] Idle Timeouts
    - [ ] Immediate Close
    - [ ] Stateless Resets
- [ ] Error Handling - [RFC 9000 - Sec 11](https://datatracker.ietf.org/doc/html/rfc9000#section-11)
- [ ] Packet Handling - [RFC 9000 - Sec 13](https://datatracker.ietf.org/doc/html/rfc9000#section-13)
    - [ ] Out-of-order packet buffering
    - [ ] Drop invalid packets
    - [ ] Drop duplicate packets
    - [ ] Resend un-acked packets
    - [ ] Generating Acknowledgments
- [ ] Datagram Size - [RFC 9000 - Sec 14](https://datatracker.ietf.org/doc/html/rfc9000#section-14)
- [ ] Async API for accepting Connections
- [ ] Async API for Streams (open, close, tx, rx)

### Beta (cleanup/rewrite) TODO's
- [ ] Rewrite Alpha (clean code from the ground up)
- [ ] A proper / robust Handshake algorithm that handles versions negotiation, 0RTT data, etc...
- [ ] A proper / robust ACK Handler / Emitter
- [ ] A proper / robust Connection Muxer
- [ ] A proper / robust Stream Muxer
- [ ] Connection State Management
- [ ] Stream State Management
- [ ] Connection and Stream termination / clean up
- [ ] Connection and Stream API
- [ ] ... Everything else 😅

### HTTP3
- [ ] HTTP3 support

> There's loads to do, so if you can, please feel free to contribute to the project 🤝

> If you have any questions or comments please start a discussion, we're happy to chat!

### Credit
- [SwiftNIO](https://github.com/apple/swift-nio) - Most of the NIO networking code is heavily inspired by existing NIO projects. Massive thanks and credit to the SwiftNIO team.
- [Quiche](https://github.com/cloudflare/quiche/tree/master)
- [Go Quic](https://github.com/quic-go/quic-go)
- [Kenneth Laskoski](https://github.com/kennethlaskoski) for kickstarting this effort!

[QUIC]: https://www.rfc-editor.org/info/rfc9000
[Swift]: https://www.swift.org/about
