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
            url: "https://github.com/wultra/cc7/releases/download/0.5.0/openssl-3.4.0.xcframework.zip",
            checksum: "0a42610074ce2ce350f6f025b508b82840489748cdc48f093f93d276ecbf1c55")
    ]
)
