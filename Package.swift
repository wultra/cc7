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
            url: "https://github.com/wultra/cc7/releases/download/0.4.1/openssl-1.1.1t.xcframework.zip",
            checksum: "863623d21d9987ea736048bc9b447a5b0a034a854c549352af91f2bd2eb824b4")
    ]
)
