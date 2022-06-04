import XCTest
@testable import Quic

final class QuicTests: XCTestCase {
    func testExample() throws {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct
        // results.
      XCTAssertEqual(Server().text(), "Hello, World!")
    }
}
