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
            url: "https://github.com/wultra/cc7/releases/download/0.5.1/openssl-3.4.1.xcframework.zip",
            checksum: "1b9cf405e04469b6066477ebb7d2957aca5e13ae1b159af1a6736e4c32f683db")
    ]
)
