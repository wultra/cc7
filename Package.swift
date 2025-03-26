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
            url: "https://github.com/wultra/cc7/releases/download/0.7.0-alpha1/openssl-3.5.0-beta1.xcframework.zip",
            checksum: "1bf4643d72462351f803f45497da7b0aded0fee6860965ebdb028b4da4b72165")
    ]
)
