// swift-tools-version: 5.6

import PackageDescription

let package = Package(
  name: "swift-quic",
  platforms: [.macOS(.v10_15)],
  products: [
    .library(
      name: "QuicCore",
      targets: ["QuicCore"]
    ),
    .library(
      name: "Quic",
      targets: ["Quic"]
    ),
  ],
  dependencies: [
    .package(url: "https://github.com/PureSwift/Socket.git", from: "0.0.0")
  ],
  targets: [
    .target(
      name: "QuicCore",
      dependencies: []
    ),

    .target(
      name: "Quic",
      dependencies: [
        "QuicCore",
        .product(name: "Socket", package: "Socket")
      ]
    ),
    .testTarget(
      name: "QuicTests",
      dependencies: ["Quic"]
    ),
  ]
)
