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
    
    func testInRef() {
        let str = "abc"
        let cstr = str.cStringUsingEncoding(NSUTF8StringEncoding)
        let data = NSData(bytes: cstr!, length: str.utf8.count)
        
        let hash = SwiftCrypton(data: data).getSHA256String()
        print(hash)
        XCTAssertEqual(hash, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    }
    
    func testPerformanceExample() {
        // This is an example of a performance test case.
        self.measureBlock {
            // Put the code you want to measure the time of here.
        }
    }
    
}
