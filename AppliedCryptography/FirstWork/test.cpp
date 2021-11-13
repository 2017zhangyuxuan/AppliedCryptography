//
// Created by 张宇轩 on 2021/11/3.
//

#include "test.h"
#include "sm4.h"
#include <iostream>
#include <hex.h>
#include <fstream>

using namespace std;
// 进行所有测试
void Test::TestAll() {
    Test::TestEncDec();                  // 测试SM4 单次加解密128bits

    Test::TestEncDecFileECB();           // 测试SM4 加密和解密文件 ECB模式

    Test::TestEncDecFileCBC();           // 测试SM4 加密和解密文件 CBC模式

    Test::TestEncDecPNG();               // 测试SM4 加密和解密PNG图片
}

// 测试SM4 单次加解密128bits
void Test::TestEncDec() {
    cout << "开始测试SM4 加解密128bits..." << endl;
    SM4 a("123");
    word32 words[4] = {13112,2223,344,41};
    for (int i =0 ;i<4;i++) {
        cout << "Source words[" << i <<"]:" << words[i] << endl;
    }
    cout << endl;
    a.Encryption(words);
    for (int i =0 ;i<4;i++) {
        cout << "Encryption words[" << i <<"]:" << words[i] << endl;
    }
    cout << endl;
    a.Decryption(words);
    for (int i =0 ;i<4;i++) {
        cout << "Decryption words[" << i <<"]:" << words[i] << endl;
    }
    cout << "------------------------------------" << endl;

    // 使用CryptoPP库 中的测试数据
    cout << "使用CryptoPP库中的测试数据" << endl;
    std::string key = "EB23ADD6454757555747395B76661C9A";
    std::string plain = "D294D879A1F02C7C5906D6C2D0C54D9F";
    std::string cipher = "865DE90D6B6E99273E2D44859D9C16DF";
    word32 keys[4];
    word32 plainData[4];

    for (int i=0 ;i<4;i++) {
        keys[i] = Hex::HexDecodeToInt(key.substr(i*8,8));
        plainData[i] = Hex::HexDecodeToInt(plain.substr(i*8,8));
    }
    a.setKey(keys);

    cout << "使用的Key(Hex)：" << endl;
    cout << key << endl;
    cout << "明文数据（Hex)：" << endl;
    cout << plain << endl;
    cout << "实际加密结果（Hex）" << endl;
    cout << cipher << endl;

    // 加密
    a.Encryption(plainData);
    cout << "测试加密结果（Hex）：" << endl;
    for (int i=0;i<4;i++) {
        cout << Hex::HexEncode(plainData[i]);           // 对输出字节 进行Hex编码
    }
    cout << endl;

    // 解密
    a.Decryption(plainData);
    cout << "测试解密结果（Hex）：" << endl;
    for (int i=0;i<4;i++) {
        cout << Hex::HexEncode(plainData[i]);
    }
    cout << endl;
    cout << "------------------------------------" << endl;

}

// 测试SM4 加密和解密文件 ECB模式
void Test::TestEncDecFileECB() {
    cout << "开始测试加密和解密文件内容(ECB模式）" << endl;
    SM4 s;

    std::string key = "11E3790F430B4729DA1EEF291BCE99CD";
    std::string plain = "04A36E56B2032B725DDE112FCE3F8398";
    word32 keys[4];

    for (int i=0 ;i<4;i++) {
        keys[i] = Hex::HexDecodeToInt(key.substr(i*8,8));
    }
    s.setKey(keys);

    // 用Hex 解码后写入文件
    std::string p = Hex::HexDecode(plain);

    fstream in;
    in.open("test/encECB.txt", ios::trunc | ios::out | ios::in);
    in.write(p.data(), 16);
    in.close();

    cout << "明文数据内容(Hex):" << endl;
    Util::printFileWithHex("test/encECB.txt");
    cout << endl;
    cout << "------------------------------------" << endl;

    // 进行文件加密
    cout << "密文数据内容(Hex):" << endl;
    s.EncFile("test/encECB.txt", "test/enc.txt");
    Util::printFileWithHex("test/enc.txt");
    cout << endl;
    cout << "------------------------------------" << endl;

    // 进行文件解密
    cout << "解密数据内容(Hex):" << endl;
    s.DecFile("test/enc.txt", "test/dec.txt");
    Util::printFileWithHex("test/dec.txt");
    cout << endl;
    cout << "------------------------------------" << endl;

    cout << "加密多结果出16字节是因为，最后增加了16个字节的padding" << endl;
    cout << "------------------------------------" << endl;

}

// 测试SM4 加密和解密文件 CBC模式
void Test::TestEncDecFileCBC() {
    // 测试 CBC 模式
    cout << "开始测试加密和解密文件内容(CBC模式）" << endl;
    SM4 s;

    std::string key = "B60B64598B7C3B4CACE7F79E0E6A04E4";
    std::string iv = "3976D813A095B411050652196B88F85D";
    std::string plain = "20D88FA20206E4C05B173659B9EB40934534C3528544B7EC1160143C612BA781";
    word32 keys[4];
    word32 IV[4];

    for (int i=0 ;i<4;i++) {
        keys[i] = Hex::HexDecodeToInt(key.substr(i*8,8));
        IV[i] = Hex::HexDecodeToInt(iv.substr(i*8,8));
    }
    s.setKey(keys);
    s.setIV(IV);

    // 用Hex 解码后写入文件
    std::string p = Hex::HexDecode(plain);

    fstream in;
    in.open("test/encCBC.txt", ios::trunc | ios::out | ios::in);
    in.write(p.data(), 32);
    in.close();

    cout << "明文数据内容(Hex):" << endl;
    Util::printFileWithHex("test/encCBC.txt");
    cout << endl;
    cout << "------------------------------------" << endl;

    // 进行文件加密
    cout << "密文数据内容(Hex):" << endl;
    s.EncFile("test/encCBC.txt", "test/enc.txt",1);
    Util::printFileWithHex("test/enc.txt");
    cout << endl;
    cout << "------------------------------------" << endl;

    // 进行文件解密
    cout << "解密数据内容(Hex):" << endl;
    s.DecFile("test/enc.txt", "test/dec.txt",1);
    Util::printFileWithHex("test/dec.txt");
    cout << endl;
    cout << "------------------------------------" << endl;

    cout << "加密多结果出16字节是因为，最后增加了16个字节的padding" << endl;
    cout << "------------------------------------" << endl;

}

// 测试SM4 加密和解密PNG图片
void Test::TestEncDecPNG() {
    SM4 s;
    std::string key = "B60B64598B7C3B4CACE7F79E0E6A04E4";
    std::string iv = "3976D813A095B411050652196B88F85D";
    word32 keys[4];
    word32 IV[4];
    s.setKey(keys);
    s.setIV(IV);

    for (int i=0 ;i<4;i++) {
        keys[i] = Hex::HexDecodeToInt(key.substr(i*8,8));
        IV[i] = Hex::HexDecodeToInt(iv.substr(i*8,8));
    }

    // ECB加密 与 解密
    s.EncPNG("test/logo.png", "test/ECB.png");
    s.DecPNG("test/ECB.png","test/ECB_logo.png");

    // CBC加密 与 解密
    s.EncPNG("test/logo.png", "test/CBC.png", 1);
    s.DecPNG("test/CBC.png","test/CBC_logo.png", 1);
}