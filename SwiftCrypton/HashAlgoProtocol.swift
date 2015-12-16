//
//  HashAlgoProtocol.swift
//  Crypton
//
//  Created by 大出喜之 on 2015/12/14.
//  Copyright © 2015年 yoshiyuki ohde. All rights reserved.
//

import Foundation

protocol HashAlgoProtocol {
    func getHashedByteArray(bytes: [UInt8]) -> [UInt8]
    func getHashedByteArray(data: NSData) -> [UInt8]
}