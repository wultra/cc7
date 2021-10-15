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
            url: "https://github.com/wultra/cc7/releases/download/0.3.5/openssl-1.1.1l.xcframework.zip",
            checksum: "bc530c2c66be2970d0f3f2d39f49cf5f0352eff52008645822d416ba985236e4")
    ]
)
