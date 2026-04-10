// swift-tools-version:5.3
import PackageDescription

let package = Package(
    name: "openssl",
    platforms: [
        .iOS(.v9),
        .tvOS(.v9)
    ],
    products: [
        .library(name: "openssl", targets: ["openssl"])
    ],
    targets: [
        .binaryTarget(
            name: "openssl",
            url: "https://github.com/wultra/cc7/releases/download/0.7.0-beta5/openssl-3.5.5.xcframework.zip",
            checksum: "a7db7726f1897392b1c9a98a64c9fd09667c4853bd4464b7cd455d650e8be2e4")
    ]
)
