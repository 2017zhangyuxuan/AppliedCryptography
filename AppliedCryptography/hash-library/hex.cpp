//
// Created by 张宇轩 on 2021/9/30.
//

#include "hex.h"

//* 将数据d用16进制编码，返回值即是结果
std::string Hex::HexEncode(const std::string& d)
{
    std::string hex;
    hex.resize(d.size() * 2);
    char* pHexData = (char*)hex.data();
    const unsigned char* pSrcData = (const unsigned char*)d.data();
    for(int i = 0; i < d.size(); i++)
    {
        pHexData[i*2]     = ToHexUpper(pSrcData[i] >> 4);
        pHexData[i*2 + 1] = ToHexUpper(pSrcData[i] & 0xf);
    }

    return hex;
}


//* 将数据d用16进制解码，返回值即是结果
std::string Hex::HexDecode(const std::string& hex)
{
    std::string res;
    res.resize(hex.size() + 1 / 2);
    unsigned char* pResult = (unsigned char*)res.data() + res.size();
    bool odd_digit = true;

    for(int i = hex.size() - 1; i >= 0; i--)
    {
        unsigned char ch = (unsigned char)(hex.at(i));
        int tmp = FromHex(ch);
        if (tmp == -1)
            continue;
        if (odd_digit) {
            --pResult;
            *pResult = tmp;
            odd_digit = false;
        } else {
            *pResult |= tmp << 4;
            odd_digit = true;
        }
    }

    res.erase(0, pResult - (unsigned char*)res.data());

    return res;
}

// 将int类型（4字节）数据进行Hex编码
std::string Hex::HexEncode(const unsigned int num) {
    std::string hex;
    hex.resize(8);
    char* pHexData = (char*)hex.data();
    for (int i=0;i<8;i++) {
        pHexData[i] = ToHexUpper(num >> ((7-i)*4));
    }
    return hex;
}

// 将8位16进制  解码成int，并且是大端模式
unsigned int Hex::HexDecodeToInt(const std::string& s) {
    std::string dec = HexDecode(s);
    unsigned char tmp[4];
    for (int i=0;i<4;i++) {
        tmp[i] = dec[i];
    }
    return (tmp[0] << 24) | (tmp[1] << 16) | (tmp[2] << 8) | tmp[3];
}