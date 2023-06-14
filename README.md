# swift-quic

Swift implementation of the IETF [QUIC](https://quicwg.github.io/) protocol.

### Welcome to the Development Branch of Swift QUIC
> ⚠️ As the name suggests, this branch is under heavy development and isn't guaranteed to build / run without errors.

### Current Progress
- [x] Complete a standard handshake using TLS 1.3
- [x] Open a stream and echo data
> Note: The above can be done between either...
>    - A [Swift Server and Client](https://github.com/kennethlaskoski/swift-quic/tree/develop/Tests/QuicTests/NIOTests/HandshakeTests.swift) or
>    - Between Swift and Go (using the [Go Quic](https://github.com/quic-go/quic-go) library)
>        - Check out the [GoInteropTests](https://github.com/kennethlaskoski/swift-quic/tree/develop/Tests/QuicTests/NIOTests/GoInteropTests) for more info.

### TODO's
- [ ] A proper / robust Handshake algorithm that handles versions negotiation, 0RTT data, etc...
- [ ] A proper / robust ACK Handler / Emitter
- [ ] A proper / robust Connection Muxer
- [ ] A proper / robust Stream Muxer
- [ ] Connection State Management
- [ ] Stream State Management
- [ ] Connection and Stream termination / clean up
- [ ] HTTP3 support
- [ ] ... Everything else 😅
> There's loads to do, so if you can, please feel free to contribute to the project 🤝


### Credit
- [SwiftNIO](https://github.com/apple/swift-nio) - Most of the NIO networking code is heavily inspired by existing NIO projects. Massive thanks and credit to the SwiftNIO team.
- [Quiche](https://github.com/cloudflare/quiche/tree/master)
- [Go Quic](https://github.com/quic-go/quic-go)
- [Kenneth Laskoski]](https://github.com/kennethlaskoski) for kickstarting this effort!
