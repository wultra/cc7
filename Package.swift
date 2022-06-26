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
            url: "https://github.com/wultra/cc7/releases/download/0.3.6/openssl-1.1.1p.xcframework.zip",
            checksum: "f2360187f82e0e8cc8f116efb7cf02bb1f8e2b0cd64f5e9e8a5076cdb6b1f797")
    ]
)
