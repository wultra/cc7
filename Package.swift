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
            url: "https://github.com/wultra/cc7/releases/download/0.4.2/openssl-1.1.1t.xcframework.zip",
            checksum: "faeaa2f194753f820f1fcc1fdf9acabcf29323dcd468390dc9c12ed20e03de6f")
    ]
)
