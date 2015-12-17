//
//  SwiftCryptonTests.swift
//  SwiftCryptonTests
//
//  Created by 大出喜之 on 2015/12/17.
//  Copyright © 2015年 yoshiyuki ohde. All rights reserved.
//

import XCTest
@testable import SwiftCrypton

class SwiftCryptonTests: XCTestCase {
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    //SHA256 Single Block Test
    func testSingleBlockSHA256() {
        let str = "abc"
        let cstr = str.cStringUsingEncoding(NSUTF8StringEncoding)
        let data = NSData(bytes: cstr!, length: str.utf8.count)
        
        let hash = SwiftCrypton(data: data).getSHA256String()
        XCTAssertEqual(hash, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    }
    
    //SHA256 Multi Block Test
    func testMultiBlockSHA256() {
        let str = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        let cstr = str.cStringUsingEncoding(NSUTF8StringEncoding)
        let data = NSData(bytes: cstr!, length: str.utf8.count)
        
        let hash = SwiftCrypton(data: data).getSHA256String()
        XCTAssertEqual(hash, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
    }
    
    //SHA1 Single Block Test
    func testSingleBlockSHA1() {
        let str = "abc"
        let cstr = str.cStringUsingEncoding(NSUTF8StringEncoding)
        let data = NSData(bytes: cstr!, length: str.utf8.count)
        
        let hash = SwiftCrypton(data: data).getSHA1String()
        XCTAssertEqual(hash, "a9993e364706816aba3e25717850c26c9cd0d89d")
    }
    
    //SHA1 Single Block Test
    func testMultiBlockSHA1() {
        let str = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        let cstr = str.cStringUsingEncoding(NSUTF8StringEncoding)
        let data = NSData(bytes: cstr!, length: str.utf8.count)
        
        let hash = SwiftCrypton(data: data).getSHA1String()
        XCTAssertEqual(hash, "84983e441c3bd26ebaae4aa1f95129e5e54670f1")
    }
    
    //SHA1 Single Block Test
    func testHelloBlockSHA1() {
        let str = "こんにちは"
        let cstr = str.cStringUsingEncoding(NSUTF8StringEncoding)
        let data = NSData(bytes: cstr!, length: str.utf8.count)
        
        let hash = SwiftCrypton(data: data).getSHA1String()
        XCTAssertEqual(hash, "20427a708c3f6f07cf12ab23557982d9e6d23b61")
    }
    
    func testPerformanceExample() {
        // This is an example of a performance test case.
        self.measureBlock {
            // Put the code you want to measure the time of here.
        }
    }
    
}
