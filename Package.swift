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
            url: "https://github.com/wultra/cc7/releases/download/0.7.0-rc1/openssl-3.5.6.xcframework.zip",
            checksum: "75f8e7ed74e27e467981621fd3ffaafd7ea2ffed080c6480cc586eb541c55e6b")
    ]
)
