//
// Created by 张宇轩 on 2021/11/3.
//

#ifndef APPLIEDCRYPTOGRAPHY_SM4_H
#define APPLIEDCRYPTOGRAPHY_SM4_H
#include "util.h"
#include <string>

class SM4 {
public:     // 暂时设计成public，方便调试
    static const byte S[256];           // 定义Sbox
    static const word32 FK[4];          // 定义参数FK，用于初始化轮密钥相关值
    static const word32 CK[32];         // 定义CK，用于生成轮密钥

    word32 IV[4];                        // 用于CBC模式
    word32 keys[4];                      // 密钥, 应注意的是keys整体是大端，但是单个word32是小端
    word32 RK[32];                       // 轮密钥

    // 根据传入的字符串，生成SM4所需的128bits 密钥 或者 IV
    void GenerateKeys(std::string key, word32 words[4]);
    void GenerateRK();                   // 根据密钥生轮密钥

    word32 Sbox(word32 word);            // 使用Sbox进行替换
    word32 LinerFunc(word32 word);       // 加密过程中的线性函数
    word32 LinerFuncRK(word32 word);     // 生成轮密钥使用的线性函数

    void SM4EncRound(word32 message[4], word32 RK);       // SM4中一轮加密，加密结果直接设置在传入数组上
    void SM4DecRound(word32 crypto[4], word32 RK);        // SM4中一轮解密

    // 辅助函数，从in读入输出到out，round循环次数，bufferSize每次读取写入的大小
    void transFile(std::fstream& in, std::fstream& out, int round, int bufferSize);

public:
    SM4();                               // 不指定，默认密钥为0
    SM4(std::string key);                // 指定密钥

    void setKey(word32 key[4]);          // 指定密钥
    void setIV(word32 iv[4]);            // 指定IV，用于CBC模式加解密

    void Encryption(word32 message[4]);  // 加密
    void Decryption(word32 crypto[4]);   // 解密

    // inputFile：待加密文件路径，encFile：加密后的文件输出路径，mode：选择加密模式，默认为ECB模式加密
    void EncFile(std::string inputFile, std::string encFile, int mode = 0);     // 0-ECB，1-CBC，2-CTR

    // encFile：加密文件输入路径，decFile：解密后文件的输出路径，mode：选择解密模式，默认为ECB模式解密
    void DecFile(std::string encFile, std::string decFile, int mode = 0);

    // 使用ECB模式加密
    void EncFileWithECB(std::fstream &in, std::fstream &out);

    // 使用ECB模式解密
    void DecFileWithECB(std::fstream &in, std::fstream &out);

    // 使用CBC模式加密
    void EncFileWithCBC(std::fstream &in, std::fstream &out);

    // 使用CBC模式解密
    void DecFileWithCBC(std::fstream &in, std::fstream &out);

    // 加密PNG图像时，应为PNG文件有特殊的格式，所以需要特比处理
    void EncPNG(std::string png, std::string encPng, int mode = 0);

    void DecPNG(std::string encPng, std::string decPng, int mode = 0);
};


#endif //APPLIEDCRYPTOGRAPHY_SM4_H
