//
//  HashAlgo.swift
//  Crypton
//
//  Created by 大出喜之 on 2015/12/14.
//  Copyright © 2015年 yoshiyuki ohde. All rights reserved.
//

import Foundation

class HashAlgo {
    
    let word:UInt32 = 32
    
    //The right shift operation SHR n(x),
    //SHR n(x) = x >> n.
    func SHR(x: UInt32, n: UInt32) -> UInt32 {
        return x >> n
    }
    
    //The rotate right (circular right shift) operation ROTR n(x)
    //ROTRn(x)=(x>>n)v (x<<w-n). here n i 0..<w .
    func ROTR(x: UInt32, n: UInt32) -> UInt32 {
        return (x >> n) | (x << (word - n))
    }
    
    //The rotate left (circular left shift) operation ROTL n(x)
    //ROTLn(x)=(x<<n)v (x>>w-n). here n i 0..<w .
    func ROTL(x: UInt32, n: UInt32) -> UInt32 {
        return (x << n) | (x >> (word-n))
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
    
    /// SHA2, SHA1のパディング処理済みのバイト配列を返す
    /// - parameter bytes: 入力データのバイト配列
    /// - returns:UInt8配列
    func getUInt8ArrayWithPadding(bytes: [UInt8]) -> [UInt8] {
        //入力データのビット長を取得
        let bytesBitCount = UInt64(bytes.count * 8)
        //バイト配列の末尾に'1'bit(0x80)を追加
        var rtnBytes = bytes
        rtnBytes.append(0x80)
        
        //ブロック数を算出
        var blockCount = rtnBytes.count / 64 + 1
        //最後のブロックが56バイト超えていたらブロックを1つ増やす
        if (rtnBytes.count % 64) > 56 {
            blockCount++
        }
        //ブロック数いっぱいまで、0x00を埋める
        for _ in rtnBytes.count ..< (blockCount * 64) {
            rtnBytes.append(0x00)
        }
        
        //入力データのビット長を64bit(8Byte)で末尾に設定
        let bitCount = rtnBytes.count
        rtnBytes[bitCount - 8] = UInt8((bytesBitCount & 0xff00000000000000) >> UInt64(56))
        rtnBytes[bitCount - 7] = UInt8((bytesBitCount & 0x00ff000000000000) >> UInt64(48))
        rtnBytes[bitCount - 6] = UInt8((bytesBitCount & 0x0000ff0000000000) >> UInt64(40))
        rtnBytes[bitCount - 5] = UInt8((bytesBitCount & 0x000000ff00000000) >> UInt64(32))
        rtnBytes[bitCount - 4] = UInt8((bytesBitCount & 0x00000000ff000000) >> UInt64(24))
        rtnBytes[bitCount - 3] = UInt8((bytesBitCount & 0x0000000000ff0000) >> UInt64(16))
        rtnBytes[bitCount - 2] = UInt8((bytesBitCount & 0x000000000000ff00) >> UInt64(8))
        rtnBytes[bitCount - 1] = UInt8(bytesBitCount & 0x00000000000000ff)
        
        return rtnBytes
    }
    
    // UInt32配列からindexで指定されたメッセージブロック(長さ16のUInt32配列。合計64Byte)を返す
    func getMsgBlockByIndex(words : [UInt32], index:Int) -> [UInt32] {
        var rtnArray = [UInt32]()
        for n in index*16 ..< (index+1)*16 {
            rtnArray.append(words[n])
        }
        return rtnArray
    }
    
    // バイト配列からUInt32配列を返す
    func getUInt32Array(bytes: [UInt8]) -> [UInt32] {
        let length = bytes.count / ( Int(word) / 8)
        var rtnArray = [UInt32]()
        for n in 0..<length {
            rtnArray.append(getUInt32ByIndex(bytes, n: n))
        }
        return rtnArray
    }
    
    // バイト配列から指定されたindexの4バイト値を取得
    private func getUInt32ByIndex(bytes: [UInt8], n: Int) -> UInt32 {
        let count = Int(word) / 8
        var rtnValue:UInt32 = 0
        for i in 0 ..< count {
            rtnValue += UInt32(bytes[count*n+i]) << UInt32(Int(word)-8*(i+1))
        }
        return rtnValue
    }
    
    func Ch(x:UInt32, y:UInt32, z:UInt32) -> UInt32 {
        return (x & y) ^ (~x & z)
    }
    
    func Maj(x:UInt32, y:UInt32, z:UInt32) -> UInt32 {
        return (x & y) ^ (x & z) ^ (y & z)
    }
    
    //デバッグ確認用メソッド
    func dump_hash(n:Int, t: Int, dmp: [UInt32]){
        print("n =", n, " , t =",t, terminator:" ")
        for item in dmp {
          print(String(format:"%08X ",item), terminator:"")
        }
        print("")
    }
}






