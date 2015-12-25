//
//  SHA1.swift
//  SwiftCrypton
//
//  Created by 大出喜之 on 2015/12/18.
//  Copyright © 2015年 yoshiyuki ohde. All rights reserved.
//

import Foundation

class SHA1 : HashAlgo, HashAlgoProtocol {
    // SHA-1 Initial hash values
    var h0:UInt32 = 0x67452301
    var h1:UInt32 = 0xefcdab89
    var h2:UInt32 = 0x98badcfe
    var h3:UInt32 = 0x10325476
    var h4:UInt32 = 0xc3d2e1f0
    
    // SHA-1 Constants
    let k: [UInt32] = [0x5a827999,0x6ed9eba1,0x8f1bbcdc, 0xca62c1d6]
    
    func getHashedByteArray(data: NSData) -> [UInt8] {
        return getHashedByteArray(self.toUInt8Array(data))
    }
    
    func getHashedByteArray(bytes: [UInt8]) -> [UInt8] {
        //パディング処理
        let paddedArray = getUInt8ArrayWithPadding(bytes)
        
        //ハッシュ計算
        //バイト配列から4バイト配列に変換
        let uintArray = getUInt32Array(paddedArray)

        var a: UInt32
        var b: UInt32
        var c: UInt32
        var d: UInt32
        var e: UInt32
        
        var T: UInt32
        
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
            
            for t in 0..<80 {
                T = ROTL(a,n:5) &+ f(t,x:b,y:c,z:d) &+ e &+ getK(t) &+ extBlock[t]
                e = d
                d = c
                c = ROTL(b, n:30)
                b = a
                a = T
                
                #if DEBUG
                    dump_hash(index,t:t,dmp: [a,b,c,d,e])
                #endif
            }
            
            h0 = a &+ h0
            h1 = b &+ h1
            h2 = c &+ h2
            h3 = d &+ h3
            h4 = e &+ h4
        }
        
        let rtnArray = [h0,h1,h2,h3,h4]
        return toUInt8Array(rtnArray)
    }
    
    //メッセージブロック(長さ16のUInt32配列)から拡張メッセージブロックを返す
    private func getExtendedMsgBlock(msgBlock: [UInt32]) -> [UInt32] {
        var rtnArray = msgBlock
        for i in 16 ..< 80 {
            rtnArray.append(ROTL(rtnArray[i-3] ^ rtnArray[i-8] ^ rtnArray[i-14] ^ rtnArray[i-16], n: 1))
        }
        return rtnArray
    }
    
    // return SHA-1 Constants K
    private func getK(t: Int) -> UInt32 {
        switch t {
            case (0...19):
                return k[0]
            case (20...39):
                return k[1]
            case (40...59):
                return k[2]
            default:
                return k[3]
        }
    }
    
    private func f(t: Int, x: UInt32, y: UInt32, z: UInt32) -> UInt32 {
        switch  t {
            case (0...19):
                return Ch(x,y:y,z:z)
            case (20...39):
                return Parity(x, y: y, z: z)
            case (40...59):
                return Maj(x, y: y, z: z)
            default:
                return Parity(x, y: y, z: z)
        }
    }
    
    private func Parity(x: UInt32, y: UInt32, z: UInt32) -> UInt32 {
        return x ^ y ^ z
    }
}





