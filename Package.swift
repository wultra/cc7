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
            url: "https://github.com/wultra/cc7/releases/download/0.7.0-beta3/openssl-3.5.5.xcframework.zip",
            checksum: "c31bc63a70ffd99e5f148536347133f5916d0eba511cd03008fd59f5d1e87459")
    ]
)
