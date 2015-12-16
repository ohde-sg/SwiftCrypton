//
//  Crypton.swift
//  Crypton
//
//  Created by 大出喜之 on 2015/12/10.
//  Copyright © 2015年 yoshiyuki ohde. All rights reserved.
//
//  Reference : http://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf

import Foundation

public enum HashAlgorithm {
    case SHA256 //SHA-256 Secure Hash Algorithm
}

public class SwiftCrypton {
    var data : NSData
    
    public init(data: NSData){
        self.data = data
    }
    
    public func getHashedArray(algorithm: HashAlgorithm) -> [UInt8] {
        switch algorithm {
        case .SHA256:
            return getSHA256ByteArray()
        }
    }
    
    //SHA-256ハッシュ値をバイト配列で返す
    private func getSHA256ByteArray() -> [UInt8]{
        //入力データをバイト配列に変換し、SHA-256アルゴリズムでハッシュ化
        return SHA256().getHashedByteArray(data)
    }
    
    /// initで設定したNSDataのSHA-256ハッシュ値を文字列で返す
    /// - returns: SHA-256ハッシュ文字列
    public func getSHA256String() -> String {
        var sha256Str : String = ""
        for item in getSHA256ByteArray() {
            sha256Str += String(format:"%02x",item)
        }
        return sha256Str
    }
}