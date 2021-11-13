//
// Created by 张宇轩 on 2021/11/3.
//

#include <iostream>
#include <fstream>
#include <vector>
#include "sm4.h"
#include "sha256.h"
#include "hex.h"


// 定义SM4 中的 Sbox
const byte SM4::S[256] = {
        0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
        0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
        0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
        0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
        0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
        0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
        0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
        0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
        0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
        0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
        0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
        0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
        0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
        0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
        0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
        0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48
};

// 定义参数FK，用于初始化轮密钥相关值
const word32 SM4::FK[4] = {
        0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC
};

// 定义SM4中的 CK，用于生成轮密钥
const word32 SM4::CK[32] = {
        0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
        0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
        0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
        0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
        0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
        0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
        0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
        0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
};

// 不指定，默认密钥为字符123456
SM4::SM4() {
    GenerateKeys("123456", keys);
    GenerateKeys("78910", IV);
    GenerateRK();
}

// 指定密钥
SM4::SM4(std::string key) {
    GenerateKeys(key, keys);
    GenerateKeys("78910", IV);
    GenerateRK();
}

// 使用Sbox进行替换
word32 SM4::Sbox(word32 word) {
    byte bytes[4];
    for (int i = 0; i < 4; i++) {
        bytes[i] = S[(word >> (3 - i) * 8) & 0xff];
    }
    return (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
}

// 加密过程中的线性函数
word32 SM4::LinerFunc(word32 word) {
    return word ^ rotlFixed(word, 2) ^ rotlFixed(word, 10) ^ rotlFixed(word, 18) ^ rotlFixed(word, 24);
}

// 生成轮密钥使用的线性函数
word32 SM4::LinerFuncRK(word32 word) {
    return word ^ rotlFixed(word, 13) ^ rotlFixed(word, 23);
}

// 根据传入的字符串，生成128bits的密钥；通过对字符串进行sha256，对得到的hash 取前128bits
void SM4::GenerateKeys(std::string key, word32 words[4]) {
    Hex hex;
    SHA256 sha256;
    std::string hash = sha256(key);             // 进行sha256哈希，输出64位的Hex编码
    hash = hash.substr(0, 32);           // 取32位的Hex，对应16字节
    for (int i = 0; i < 4; i++) {
        words[i] = hex.HexDecodeToInt(hash.substr(8 * i, 8));
    }
}

// 生成轮密钥
void SM4::GenerateRK() {
    word32 InitRK[36];
    for (int i = 0; i < 4; i++) {
        InitRK[i] = keys[i] ^ FK[i];
    }
    for (int i = 4; i < 36; i++) {
        InitRK[i] = InitRK[i - 4] ^ LinerFuncRK(          // 线性函数，循环移位
                Sbox(InitRK[i - 3] ^ InitRK[i - 2] ^ InitRK[i - 1] ^ CK[i - 4]));   // Sbox置换
        RK[i - 4] = InitRK[i];            // 赋值轮密钥
    }
}

// 指定密钥
void SM4::setKey(word32 key[4]) {
    for (int i = 0; i < 4; i++) {
        keys[i] = key[i];
    }
    GenerateRK();
}

// 指定IV，用于CBC模式加解密
void SM4::setIV(word32 iv[4]) {
    for (int i = 0; i < 4; i++) {
        IV[i] = iv[i];
    }
}

// SM4中一轮加密，加密结果直接设置在传入数组上
void SM4::SM4EncRound(word32 message[4], word32 RK) {
    word32 crypto[4] = {message[1], message[2], message[3], 0};
    word32 tmp = message[1] ^ message[2] ^ message[3] ^ RK;
    crypto[3] = message[0] ^ LinerFunc(Sbox(tmp));      // 分别经过Sbox替换和线性函数

    // 赋值加密结果
    for (int i = 0; i < 4; i++) {
        message[i] = crypto[i];
    }
}

// SM4中一轮解密
void SM4::SM4DecRound(word32 crypto[4], word32 RK) {
    word32 message[4] = {0, crypto[0], crypto[1], crypto[2]};
    word32 tmp = crypto[0] ^ crypto[1] ^ crypto[2] ^ RK;
    message[0] = crypto[3] ^ LinerFunc(Sbox(tmp));      // 分别经过Sbox替换和线性函数

    // 赋值加密结果
    for (int i = 0; i < 4; i++) {
        crypto[i] = message[i];
    }
}


// 加密，对单个输入128bits 进行加密
void SM4::Encryption(word32 message[4]) {
    // 进行32轮 轮函数加密
    for (int i = 0; i < 32; i++) {
        SM4EncRound(message, RK[i]);
    }

    // 进行Permutation，调换顺序
    unsigned int tmp = message[0];
    message[0] = message[3];
    message[3] = tmp;
    tmp = message[1];
    message[1] = message[2];
    message[2] = tmp;
}

// 解密
void SM4::Decryption(word32 crypto[4]) {
    // 进行Permutation，调换顺序
    unsigned int tmp = crypto[0];
    crypto[0] = crypto[3];
    crypto[3] = tmp;
    tmp = crypto[1];
    crypto[1] = crypto[2];
    crypto[2] = tmp;

    // 进行32轮 轮函数解密
    for (int i = 0; i < 32; i++) {
        SM4DecRound(crypto, RK[31 - i]);
    }

}

// inputFile：待加密文件路径，encFile：加密后的文件输出路径，mode：选择加密模式，默认为ECB模式加密
// 0-ECB，1-CBC
void SM4::EncFile(std::string inputFile, std::string encFile, int mode) {
    std::fstream input, enc;
    // 打开文件流
    input.open(inputFile, std::ios::in);
    enc.open(encFile, std::ios::in | std::ios::out | std::ios::trunc);
    if (input.is_open() && enc.is_open()) {
        switch (mode) {         // 执行对应的加密模式
            case 0:
                EncFileWithECB(input, enc);
                break;
            case 1:
                EncFileWithCBC(input, enc);
                break;
            default:
                std::cout << "请输入正确的加密模式：0-ECB（默认），1-CBC" << std::endl;
        }
    }

    // 关闭文件流
    if (input.is_open()) {
        input.close();
    } else {
        std::cout << "未能正确打开明文文件！" << std::endl;
    }

    if (enc.is_open()) {
        enc.close();
    } else {
        std::cout << "未能正确打开写入的密文文件！" << std::endl;
    }

}


// encFile：加密文件输入路径，decFile：解密后文件的输出路径，mode：选择解密模式，默认为ECB模式解密
void SM4::DecFile(std::string encFile, std::string decFile, int mode) {
    std::fstream enc, dec;
    // 打开文件流
    enc.open(encFile, std::ios::in);
    dec.open(decFile, std::ios::in | std::ios::out | std::ios::trunc);
    if (enc.is_open() && dec.is_open()) {
        switch (mode) {         // 执行对应的解密模式
            case 0:
                DecFileWithECB(enc, dec);
                break;
            case 1:
                DecFileWithCBC(enc, dec);
                break;
            default:
                std::cout << "请输入正确的解密模式：0-ECB（默认），1-CBC" << std::endl;
        }
    }

    // 关闭文件流
    if (enc.is_open()) {
        enc.close();
    }
    if (dec.is_open()) {
        dec.close();
    }

}

// 使用ECB模式加密
void SM4::EncFileWithECB(std::fstream &in, std::fstream &out) {
    char buffer[16];
    word32 message[4];
    int cnt = 0;
    do {
        in.read(buffer, 16);            // 每次读取16字节
        cnt = in.gcount();                 // 实际读取的字节数

        // 赋值明文数据
        memcpy(message, buffer, cnt);
        // 不足一个分组，需要进行padding
        memset((void *) (reinterpret_cast<const char *>(message) + cnt), 16 - cnt, 16 - cnt);


        // 进行SM4 加密
        Encryption(message);

        // 加密结果写入文件
        out.write(reinterpret_cast<const char *>(message), 16);
    } while (cnt >= 16);
}

// 使用ECB模式解密
void SM4::DecFileWithECB(std::fstream &in, std::fstream &out) {
    char buffer[16];

    word32 crypto[4];               // 解密当前数据
    word32 preCrypto[4];            // 上一轮解密数据
    int cnt = 0;
    in.read(buffer, 16);
    memcpy(preCrypto, buffer, 16);
    Decryption(preCrypto);

    do {
        in.read(buffer, 16);            // 每次读取16字节
        cnt = in.gcount();                 // 实际读取的字节数

        // 将上一轮解密结果写入文件
        if (cnt == 0) {
            // 读到末尾了，获取最后一字节，算出padding数
            unsigned char padding = *(reinterpret_cast<unsigned char *>(preCrypto) + 15);

            out.write(reinterpret_cast<const char *>(preCrypto), 16 - padding);
        } else {
            out.write(reinterpret_cast<const char *>(preCrypto), cnt);

            // 进行这一轮解密
            memcpy(crypto, buffer, cnt);
            Decryption(crypto);

            // 覆盖前一轮解密结果
            memcpy(preCrypto, crypto, sizeof(crypto));
        }
    } while (cnt >= 16);
}

// 使用CBC模式加密
void SM4::EncFileWithCBC(std::fstream &in, std::fstream &out) {
    char buffer[16];
    word32 message[4];
    word32 cipher[4];
    int cnt = 0;
    in.read(buffer, 16);            // 先读取16字节
    cnt = in.gcount();                 // 实际读取的字节数

    // 赋值明文数据
    memcpy(cipher, buffer, cnt);       // 这里有个坑，给unsigned int拷贝时，也在遵循小端原则
    // 不足一个分组时，需要进行padding
    memset((void *) (reinterpret_cast<const char *>(cipher) + cnt), 16 - cnt, 16 - cnt);

    // 第一个分组 跟IV进行异或
    Util::XOR(cipher, IV);

    // 加密
    Encryption(cipher);

    // 加密结果写入文件
    out.write(reinterpret_cast<const char *>(cipher), 16);


    while (cnt >= 16) {
        in.read(buffer, 16);            // 每次读取16字节
        cnt = in.gcount();                 // 实际读取的字节数

        // 赋值明文数据
        memcpy(message, buffer, cnt);
        // 不足一个分组，需要进行padding
        memset((void *) (reinterpret_cast<const char *>(message) + cnt), 16 - cnt, 16 - cnt);

        // 上一次密文 跟这一次明文 异或
        Util::XOR(cipher, message);
        // 加密
        Encryption(cipher);

        // 加密结果写入文件
        out.write(reinterpret_cast<const char *>(cipher), 16);
    }
}

// 使用CBC模式解密
void SM4::DecFileWithCBC(std::fstream &in, std::fstream &out) {
    char buffer[16];
    word32 cipher[4];
    word32 message[4];
    word32 preMessage[4];              // 上一个明文分组
    int cnt = 0;
    in.read(buffer, 16);            // 先读取16字节
    cnt = in.gcount();                 // 实际读取的字节数

    // 赋值密文数据
    memcpy(message, buffer, cnt);
    memcpy(cipher, buffer, cnt);

    // 解密
    Decryption(message);
    // 得到第一个明文分组
    Util::XOR(message, IV);

    // 进行备份明文
    memcpy(preMessage, message, sizeof(message));

    while (cnt >= 16) {
        in.read(buffer, 16);            // 每次读取16字节
        cnt = in.gcount();                 // 实际读取的字节数

        // 准备将上一个得到的明文写入文件
        if (cnt == 0) {
            // 读到末尾了，获取最后一字节，算出padding数
            unsigned char padding = *(reinterpret_cast<unsigned char *>(preMessage) + 15);

            out.write(reinterpret_cast<const char *>(preMessage), 16 - padding);
        } else {
            out.write(reinterpret_cast<const char *>(preMessage), cnt);

            // 获取这一轮密文
            memcpy(message, buffer, cnt);

            // 解密
            Decryption(message);
            Util::XOR(message, cipher);

            // 覆盖前一轮的密文
            memcpy(cipher, buffer, cnt);
            // 覆盖前一轮解密结果
            memcpy(preMessage, message, sizeof(message));
        }
    }


}


// 加密PNG图像时，应为PNG文件有特殊的格式，所以需要特比处理
void SM4::EncPNG(std::string png, std::string encPng, int mode) {
    if (png.substr(png.size() - 4, 4) != ".png") {
        std::cout << "输入路径不是png格式！" << std::endl;
        return;
    }
    if (png.substr(png.size() - 4, 4) != ".png") {
        std::cout << "输出路径不是png格式！" << std::endl;
        return;
    }

    std::fstream input, enc;
    // 为了复用之前的方法，将png图片待加密的数据块读入临时文件，将加密数据写入临时文件
    std::fstream tmpInput, tmpOutput;

    // 打开文件流
    input.open(png, std::ios::in);
    enc.open(encPng, std::ios::in | std::ios::out | std::ios::trunc);

    if (input.is_open() && enc.is_open()) {
        char buffer[1];
        char src[4];
        char target[4] = {0x49,0x44,0x41,0x54};         // 对应IDAT
        char end[4] = {0,0,0,0};                        // 对应IEND

        // 定义临时文件名字
        std::string suffix = Hex::HexEncode(time(0));
        std::string inTemp = "tmp" + suffix;
        std::string outTemp = "encTemp" + suffix;

        // 前面8字节直接复制写入
        transFile(input, enc, 8 , 1);

        while(true) {
            // 读入数据块
            int tmpLenCur = enc.tellp();        // 记录当前位置
            // 第一个4字节表示该数据块的字节长度
            input.read(src, 4);
            enc.write(src, 4);
            int dataSize = (src[0] << 24) | (src[1] << 16) | (src[2] << 8) | src[3];

            // 字节长度为0，表示读到IEND
            if (Util::equalChars(src, end, 4)) {
                break;
            }

            // 第二个4字节 表示该数据块的类型
            input.read(src, 4);
            enc.write(src,4);

            // 找到IDAT 类型，对实际数据进行加密
            if (Util::equalChars(src, target, 4)) {
                // 读入数据到临时文件
                tmpInput.open(inTemp, std::ios::in | std::ios::out | std::ios::trunc);
                transFile(input, tmpInput, dataSize, 1);
                tmpInput.close();

                // 加密数据块
                EncFile(inTemp, outTemp, mode);

                // 将临时加密数据写入文件
                tmpOutput.open(outTemp, std::ios::in);
                word32 encSize = Util::getFileSize(tmpOutput);     // 加密后数据字节长度可能会比原来大

                transFile(tmpOutput, enc, encSize, 1);
                int curPos = enc.tellp();               // 记录当前位置pos
                tmpOutput.close();

                enc.seekp(tmpLenCur);                   // 回去修改数据的字节长度

                encSize = Util::changeByteOrder(encSize);   // 按大端模式写入
                enc.write(reinterpret_cast<char*>(&encSize),4);
                enc.seekp(curPos);                      // 返回之前的写入位置

            } else {
                // 其他类型直接写入
                transFile(input, enc, dataSize, 1);
            }

            // 然后需要再读取4个字节 的CRC校验码
            input.read(src, 4);
            enc.write(src,4);
        }

        // 读入最后8字节 IEND
        transFile(input, enc, 8, 1);

        // 移除临时文件
        remove(inTemp.data());
        remove(outTemp.data());
    }

    // 关闭文件流
    if (input.is_open()) {
        input.close();
    } else {
        std::cout << "未能正确打开图片文件！" << std::endl;
    }

    if (enc.is_open()) {
        enc.close();
    } else {
        std::cout << "未能正确打开加密的图片文件！" << std::endl;
    }
}

void SM4::DecPNG(std::string encPng, std::string decPng, int mode) {
    if (encPng.substr(encPng.size() - 4, 4) != ".png") {
        std::cout << "输入路径不是png格式！" << std::endl;
        return;
    }
    if (decPng.substr(decPng.size() - 4, 4) != ".png") {
        std::cout << "输出路径不是png格式！" << std::endl;
        return;
    }

    std::fstream input, dec;
    // 为了复用之前的方法，将png图片待加密的数据块读入临时文件，将加密数据写入临时文件
    std::fstream tmpInput, tmpOutput;

    // 打开文件流
    input.open(encPng, std::ios::in);
    dec.open(decPng, std::ios::in | std::ios::out | std::ios::trunc);

    if (input.is_open() && dec.is_open()) {
        char buffer[1];
        char src[4];
        char target[4] = {0x49,0x44,0x41,0x54};         // 对应IDAT
        char end[4] = {0,0,0,0};                        // 对应IEND

        // 定义临时文件名字
        std::string suffix = Hex::HexEncode(time(0));
        std::string inTemp = "tmp" + suffix;
        std::string outTemp = "decTemp" + suffix;

        // 前面8字节直接复制写入
        transFile(input, dec, 8 , 1);

        while(true) {
            // 读入数据块
            int tmpLenCur = dec.tellp();        // 记录当前位置
            // 第一个4字节表示该数据块的字节长度
            input.read(src, 4);
            dec.write(src, 4);
            int dataSize = (src[0] << 24) | (src[1] << 16) | (src[2] << 8) | src[3];

            // 字节长度为0，表示读到IEND
            if (Util::equalChars(src, end, 4)) {
                break;
            }

            // 第二个4字节 表示该数据块的类型
            input.read(src, 4);
            dec.write(src,4);

            // 找到IDAT 类型，对实际数据进行加密
            if (Util::equalChars(src, target, 4)) {
                // 读入数据到临时文件
                tmpInput.open(inTemp, std::ios::in | std::ios::out | std::ios::trunc);
                transFile(input, tmpInput, dataSize, 1);
                tmpInput.close();

                // 加密数据块
                DecFile(inTemp, outTemp, mode);

                // 将临时加密数据写入文件
                tmpOutput.open(outTemp, std::ios::in);
                word32 decSize = Util::getFileSize(tmpOutput);     // 解密后数据字节长度可能会比原来小
                transFile(tmpOutput, dec, decSize, 1);
                int curPos = dec.tellp();               // 记录当前位置pos
                tmpOutput.close();

                dec.seekp(tmpLenCur);                   // 回去修改数据的字节长度

                decSize = Util::changeByteOrder(decSize);
                dec.write(reinterpret_cast<char*>(&decSize),4);
                dec.seekp(curPos);                      // 返回之前的写入位置

            } else {
                // 其他类型直接写入
                transFile(input, dec, dataSize, 1);
            }

            // 然后需要再读取4个字节 的CRC校验码
            input.read(src, 4);
            dec.write(src,4);
        }

        // 读入最后8字节 IEND
        transFile(input, dec, 8, 1);

        // 移除临时文件
        remove(inTemp.data());
        remove(outTemp.data());
    }

    // 关闭文件流
    if (input.is_open()) {
        input.close();
    } else {
        std::cout << "未能正确打开图片文件！" << std::endl;
    }

    if (dec.is_open()) {
        dec.close();
    } else {
        std::cout << "未能正确打开加密的图片文件！" << std::endl;
    }
}

// 辅助函数，从in读入输出到out，round循环次数，bufferSize每次读取写入的大小
void SM4::transFile(std::fstream& in, std::fstream& out, int round, int bufferSize) {
    char buffer[bufferSize];
    for (int i=0;i < round; i++) {
        in.read(buffer, bufferSize);
        in.flush();
        out.write(buffer, bufferSize);
        out.flush();
    }
}


