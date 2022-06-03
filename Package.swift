// swift-tools-version: 5.6

import PackageDescription

let package = Package(
  name: "swift-quic",
  products: [
    .library(
      name: "Quic",
      targets: ["Quic"]
    ),
  ],
  dependencies: [ ],
  targets: [
    .target(
      name: "Quic",
      dependencies: []
    ),
    .testTarget(
      name: "QuicTests",
      dependencies: ["Quic"]
    ),
  ]
)
