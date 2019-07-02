import XCTest

import auditswiftTests

var tests = [XCTestCaseEntry]()
tests += auditswiftTests.allTests()
XCTMain(tests)