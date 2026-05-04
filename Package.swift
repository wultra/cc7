// swift-tools-version:6.3
import PackageDescription

// ------------------------------------------------------------------------------- //
// Do not modify this file directly. For a proper library publishing, you have to  //
//        modify "openssl-build/assets/apple/Package.swift" template file.         //
// ------------------------------------------------------------------------------- //

let package = Package(
    name: "cc7",
    platforms: [
        .iOS(.v13),
        .tvOS(.v13),
        .watchOS(.v4),
        .macCatalyst(.v13)
    ],
    products: [
        .library(name: "openssl", targets: ["openssl"]),
        .library(name: "cc7", targets: ["cc7"]),
        .library(name: "cc7tests", targets: ["cc7tests"])
    ],
    targets: [
        .binaryTarget(
            name: "openssl",
            url: "https://github.com/wultra/cc7/releases/download/0.7.0-rc1/openssl-3.5.6.xcframework.zip",
            checksum: "75f8e7ed74e27e467981621fd3ffaafd7ea2ffed080c6480cc586eb541c55e6b"
        ),
        .target(
            name: "cc7",
            dependencies: [
                .target(name: "openssl"),
            ],
            path: ".",
            exclude: [
                "src/cc7/platform/android",
            ],
            sources: [
                "src/cc7"
            ],
            publicHeadersPath: "include",
            cSettings: [
                .headerSearchPath("include"),
            ],
            cxxSettings: [
                .headerSearchPath("include"),
            ],
            linkerSettings: [
                .linkedFramework("Foundation")
            ]
        ),
        .target(
            name: "cc7tests",
            dependencies: [
                .target(name: "cc7")
            ],
            path: ".",
            exclude: [
                "src/cc7tests/platform/PerformanceTimerAndroid.cpp",
                "src/cc7tests/platform/PerformanceTimerWindows.cpp",
                "src/cc7tests/tests/test-data/",
                "src/cc7tests/tests/cc7-test-data.conf",
                "src/cc7tests/tests/update-test-data.sh",
            ],
            sources: [
                "src/cc7tests"
            ],
            cSettings: [
                .headerSearchPath("include"),
            ],
            cxxSettings: [
                .headerSearchPath("include"),
            ]
        ),
        .testTarget(
            name: "CC7TestsWrapper",
            dependencies: [
                .target(name: "cc7tests")
            ],
            path: "proj-xcode/CC7TestsWrapper",
            exclude: [
                "cc7_ios.xctestplan",
                "cc7_tvos.xctestplan",
                "cc7_watchos.xctestplan",
                "Info.plist"
            ],
            sources: [
                "."
            ],
            cSettings: [
                .headerSearchPath("../../include")
            ],
            cxxSettings: [
                .headerSearchPath("../../include")
            ]
        )
    ],
    cLanguageStandard: .c17,
    cxxLanguageStandard: .cxx20
)
