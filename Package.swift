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
            url: "https://github.com/wultra/cc7/releases/download/0.7.0-beta4/openssl-3.5.5.xcframework.zip",
            checksum: "e8a8e96d10f1b83eb3574ce24839c2e60063b7c573c9d81dab692676a2372e61")
    ]
)
