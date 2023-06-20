# swift-quic

Swift implementation of the IETF [QUIC](https://quicwg.github.io/) protocol.

[![Swift](https://github.com/swift-quic/swift-quic/actions/workflows/swift.yml/badge.svg)](https://github.com/swift-quic/swift-quic/actions/workflows/swift.yml)
[![](https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2Fswift-quic%2Fswift-quic%2Fbadge%3Ftype%3Dswift-versions)](https://swiftpackageindex.com/swift-quic/swift-quic)
[![](https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2Fswift-quic%2Fswift-quic%2Fbadge%3Ftype%3Dplatforms)](https://swiftpackageindex.com/swift-quic/swift-quic)

### Welcome to SwiftQuic
> ⚠️  This implementation is under heavy development and is not ready for production!

### Current Progress
- [x] Complete a standard handshake using TLS 1.3
- [x] Open a stream and echo data
> Note: The above can be done between either...
>    - A [Swift Server and Client](https://github.com/kennethlaskoski/swift-quic/tree/develop/Tests/QuicTests/NIOTests/HandshakeTests.swift) or
>    - Between Swift and Go (using the [Go Quic](https://github.com/quic-go/quic-go) library)
>        - Check out the [GoInteropTests](https://github.com/kennethlaskoski/swift-quic/tree/develop/Tests/QuicTests/NIOTests/GoInteropTests) for more info.

### How It Works
- All of the Crypto stuff is mostly contained with the [Crypto](https://github.com/swift-quic/swift-quic/tree/develop/Sources/Quic/Crypto) folder and the [`PacketProtectorHandler`](https://github.com/swift-quic/swift-quic/blob/develop/Sources/Quic/NIO/Connection/Handlers/PacketProtectorHandler.swift)
- The NIO Pipeline configuration is discussed [here](https://github.com/swift-quic/swift-quic/discussions/6)
- The TLS Handshake uses a slightly modified version of `swift-nio-ssl` available [here](https://github.com/btoms20/swift-nio-ssl)
- The main connection logic is handled in the `read` and `write` methods of the [Client](https://github.com/swift-quic/swift-quic/blob/develop/Sources/Quic/NIO/Connection/Handlers/ClientHandler.swift) and [Server](https://github.com/swift-quic/swift-quic/blob/develop/Sources/Quic/NIO/Connection/Handlers/ServerHandler.swift) Handlers for the time being (these will eventually be merged into a more generalized StateHandler). 

### TODO's
- [ ] A proper / robust Handshake algorithm that handles versions negotiation, 0RTT data, etc...
- [ ] A proper / robust ACK Handler / Emitter
- [ ] A proper / robust Connection Muxer
- [ ] A proper / robust Stream Muxer
- [ ] Connection State Management
- [ ] Stream State Management
- [ ] Connection and Stream termination / clean up
- [ ] HTTP3 support
- [ ] Connection and Stream API
- [ ] ... Everything else 😅
> There's loads to do, so if you can, please feel free to contribute to the project 🤝

> If you have any questions or comments please start a discussion, we're happy to chat!

### Credit
- [SwiftNIO](https://github.com/apple/swift-nio) - Most of the NIO networking code is heavily inspired by existing NIO projects. Massive thanks and credit to the SwiftNIO team.
- [Quiche](https://github.com/cloudflare/quiche/tree/master)
- [Go Quic](https://github.com/quic-go/quic-go)
- [Kenneth Laskoski](https://github.com/kennethlaskoski) for kickstarting this effort!
