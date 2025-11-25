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
            url: "https://github.com/wultra/cc7/releases/download/0.7.0-beta2/openssl-3.5.4.xcframework.zip",
            checksum: "0045762648d060bb504b6632d60fd2cb3e4468c4e11638a610046b17cf7eb8ee")
    ]
)
