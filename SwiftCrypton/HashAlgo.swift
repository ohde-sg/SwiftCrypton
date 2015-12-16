//
//  HashAlgo.swift
//  Crypton
//
//  Created by 大出喜之 on 2015/12/14.
//  Copyright © 2015年 yoshiyuki ohde. All rights reserved.
//

import Foundation

class HashAlgo {
    
    let word = 32
    
    //The right shift operation SHR n(x),
    //SHR n(x) = x >> n.
    func SHR(x: UInt32, n: UInt32) -> UInt32 {
        return x >> n
    }
    
    //The rotate right (circular right shift) operation ROTR n(x)
    //ROTRn(x)=(x>>n)v (x<<w-n). here n i 0..<w .
    func ROTR(x: UInt32, n: UInt32) -> UInt32 {
        //一旦、UInt64に拡張し、UINT32_MAXとの論理積をとり、桁あふれした分を削除
        let u = UInt64(x) << UInt64(word - Int(n))
        return (x >> n) | UInt32( u & UInt64(UINT32_MAX) )
    }
    
    /// NSData変数をUInt8配列に変換して返す
    /// - parameter data: 入力データ
    /// - returns: 入力データのバイト配列
    func toUInt8Array(data: NSData) -> [UInt8] {
        var bytes = [UInt8](count: data.length / sizeof(UInt8), repeatedValue :0)
        data.getBytes(&bytes, length: data.length)
        return bytes
    }
    
    func toUInt8Array(words: [UInt32]) -> [UInt8] {
        var rtnArray = [UInt8]()
        for item in words {
            rtnArray += toUInt8Array(item)
        }
        return rtnArray
    }
    
    func toUInt8Array(word: UInt32) -> [UInt8] {
        var rtnArray = [UInt8]()
        rtnArray.append( UInt8((word & UInt32(0xFF000000)) >> UInt32(24)))
        rtnArray.append( UInt8((word & UInt32(0x00FF0000)) >> UInt32(16)))
        rtnArray.append( UInt8((word & UInt32(0x0000FF00)) >> UInt32(8)))
        rtnArray.append( UInt8(word & UInt32(0x000000FF)))
        return rtnArray
    }
}






