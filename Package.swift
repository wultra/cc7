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
            url: "https://github.com/wultra/cc7/releases/download/0.4.0/openssl-1.1.1p.xcframework.zip",
            checksum: "963cacce9ebbb53ff1564a08c86b01e72bc08dacf6f32eff3c98182f90c33957")
    ]
)
