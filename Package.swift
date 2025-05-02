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
            url: "https://github.com/wultra/cc7/releases/download/0.7.0-beta1/openssl-3.5.0.xcframework.zip",
            checksum: "0642c28fe4f88927fa6052b1b05ca376b86f9f392be312cb1697e45af398e931")
    ]
)
