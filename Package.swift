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
            url: "https://github.com/wultra/cc7/releases/download/0.6.0/openssl-3.4.0.xcframework.zip",
            checksum: "dd08676a1d202bd885a37520f4ddd93035123c32d4e01e81e0d43411d7e971ca")
    ]
)
