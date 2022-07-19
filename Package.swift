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
            url: "https://github.com/wultra/cc7/releases/download/0.3.7/openssl-1.1.1p.xcframework.zip",
            checksum: "266b002f25ed336ab6893f88bed7cede094e879956b17ef2ef2b00cadb6e1810")
    ]
)
