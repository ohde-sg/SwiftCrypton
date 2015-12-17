//
//  SHA256.swift
//  Crypton
//
//  Created by 大出喜之 on 2015/12/14.
//  Copyright © 2015年 yoshiyuki ohde. All rights reserved.
//

import Foundation

class SHA256 : HashAlgo ,HashAlgoProtocol{
    // Initialize hash values:
    // (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
    var h0:UInt32 = 0x6a09e667 // a
    var h1:UInt32 = 0xbb67ae85 // b
    var h2:UInt32 = 0x3c6ef372 // c
    var h3:UInt32 = 0xa54ff53a // d
    var h4:UInt32 = 0x510e527f // e
    var h5:UInt32 = 0x9b05688c // f
    var h6:UInt32 = 0x1f83d9ab // g
    var h7:UInt32 = 0x5be0cd19 // h
    
    // Initialize array of round constants:
    // (first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311):
    let initK: [UInt32] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]
    
    func getHashedByteArray(data: NSData) -> [UInt8]{
        return getHashedByteArray(self.toUInt8Array(data))
    }
    
    func getHashedByteArray(bytes: [UInt8]) -> [UInt8] {
        //パディング処理
        let paddedArray = getUInt8ArrayWithPadding(bytes)
        //ハッシュ処理
        
        //バイト配列から4バイト配列に変換
        let uintArray = getUInt32Array(paddedArray)
        
        var a: UInt32
        var b: UInt32
        var c: UInt32
        var d: UInt32
        var e: UInt32
        var f: UInt32
        var g: UInt32
        var h: UInt32
        
        for index in 0..<(paddedArray.count/64) {
            //indexで指定したメッセージブロックを取得
            let msgBlock = getMsgBlockByIndex(uintArray,index:index)
            //拡張ブロックを作成
            let extBlock = getExtendedMsgBlock(msgBlock)
            
            a = h0
            b = h1
            c = h2
            d = h3
            e = h4
            f = h5
            g = h6
            h = h7
            
            var T1:UInt32 = 0
            var T2:UInt32 = 0
            
            for t in 0..<64 {
                T1 = h &+ sigmaU1(e) &+ Ch(e,y: f,z: g) &+ initK[t] &+ extBlock[t]
                T2 = sigmaU0(a) &+ Maj(a, y: b, z: c)
                h = g
                g = f
                f = e
                e = d &+ T1
                d = c
                c = b
                b = a
                a = T1 &+ T2
                
                #if DEBUG
                    dump_hash(index,t:t,dmp: [a,b,c,d,e,f,g,h])
                #endif
            }
            
            h0 = a &+ h0
            h1 = b &+ h1
            h2 = c &+ h2
            h3 = d &+ h3
            h4 = e &+ h4
            h5 = f &+ h5
            h6 = g &+ h6
            h7 = h &+ h7
        }
        
        let rtnArray = [h0,h1,h2,h3,h4,h5,h6,h7]
        
        return toUInt8Array(rtnArray)
    }
    
    //メッセージブロック(長さ16のUInt32配列)から拡張メッセージブロックを返す
    private func getExtendedMsgBlock(msgBlock: [UInt32]) -> [UInt32] {
        var rtnArray = msgBlock
        for i in 16 ..< 64 {
            rtnArray.append(sigmaL1(rtnArray[i-2]) &+ rtnArray[i-7] &+ sigmaL0(rtnArray[i-15]) &+ rtnArray[i-16])
        }
        return rtnArray
    }
    
    private func sigmaU0(x: UInt32) -> UInt32 {
        return ROTR(x,n: 2) ^ ROTR(x, n: 13) ^ ROTR(x, n: 22)
    }
    
    private func sigmaU1(x: UInt32) -> UInt32 {
        return ROTR(x,n: 6) ^ ROTR(x, n: 11) ^ ROTR(x, n: 25)
    }
    
    private func sigmaL0(x: UInt32) -> UInt32 {
        return ROTR(x,n: 7) ^ ROTR(x, n: 18) ^ SHR(x, n: 3)
    }
    
    private func sigmaL1(x: UInt32) -> UInt32 {
        return ROTR(x,n: 17) ^ ROTR(x, n: 19) ^ SHR(x, n: 10)
    }
}



















