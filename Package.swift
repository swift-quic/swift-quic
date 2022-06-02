// swift-tools-version: 5.6

import PackageDescription

let package = Package(
  name: "swift-http3",
  products: [
    .library(
      name: "Quic",
      targets: ["Quic"]
    ),
    .executable(
      name: "client",
      targets: ["EchoClient"]
    ),
    .executable(
      name: "server",
      targets: ["EchoServer"]
    ),
  ],
  dependencies: [
        // Dependencies declare other packages that this package depends on.
        // .package(url: /* package url */, from: "1.0.0"),
  ],

  targets: [
    .target(
      name: "Quic",
      dependencies: []
    ),
    .testTarget(
      name: "QuicTests",
      dependencies: ["Quic"]
    ),

    .executableTarget(
      name: "EchoClient",
      dependencies: ["Quic"],
      path: "Sources/Echo/Client"
    ),
    .testTarget(
      name: "clientTests",
      dependencies: ["EchoClient"],
      path: "Tests/EchoTests/ClientTests"
    ),

    .executableTarget(
      name: "EchoServer",
      dependencies: ["Quic"],
      path: "Sources/Echo/Server"
    ),
    .testTarget(
      name: "serverTests",
      dependencies: ["EchoServer"],
      path: "Tests/EchoTests/ServerTests"
    ),
  ]
)
