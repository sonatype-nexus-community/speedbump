// swift-tools-version:4.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "auditswift",
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        // .package(url: /* package url */, from: "1.0.0"),
        .package(url: "https://github.com/jkandzi/Progress.swift", from: "0.4.0"),
        .package(url: "https://github.com/onevcat/Rainbow", from: "3.1.4")
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages which this package depends on.
        .target(
            name: "auditswift",
            dependencies: ["Rainbow", "Progress"]),
        .testTarget(
            name: "auditswiftTests",
            dependencies: ["auditswift"]),
    ]
)
