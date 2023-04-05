// swift-tools-version: 5.6

import PackageDescription

let package = Package(
  name: "swift-quic",
  platforms: [
    .macOS(.v10_15),
    .iOS(.v13),
  ],
  products: [
    .library(
      name: "Quic",
      targets: ["Quic"]
    ),
  ],
  dependencies: [
    .package(url: "https://github.com/apple/swift-nio.git", from: "2.0.0"),
    .package(url: "https://github.com/apple/swift-crypto.git", from: "2.0.0"),
  ],
  targets: [
    .target(
      name: "Quic",
      dependencies: [
        .product(name: "NIOCore", package: "swift-nio"),
        .product(name: "NIOPosix", package: "swift-nio"),
        .product(name: "Crypto", package: "swift-crypto")
      ]
    ),
    .testTarget(
      name: "QuicTests",
      dependencies: ["Quic"]
    ),
  ]
)
