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
            url: "https://github.com/wultra/cc7/releases/download/0.4.3/openssl-1.1.1w.xcframework.zip",
            checksum: "f80952959b6694acbe0c3c7148c209426ff64e5cb6104ffacfc75d0b5e2daba8")
    ]
)
