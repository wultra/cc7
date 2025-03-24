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
            url: "https://github.com/wultra/cc7/releases/download/0.6.1/openssl-3.4.1.xcframework.zip",
            checksum: "89392ab33b6f34390c2ae222722eef08f42cc2d9c93ae1e1b5e46054a7695557")
    ]
)
