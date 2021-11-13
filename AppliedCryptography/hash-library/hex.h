//
// Created by 张宇轩 on 2021/9/30.
//

#ifndef ETHEREUMEXERCISE_HEX_H
#define ETHEREUMEXERCISE_HEX_H

#include <string>

class Hex {
public:

    // 将数字转为16进制（大写）
    static inline char ToHexUpper(unsigned int value)
    {
        return "0123456789ABCDEF"[value & 0xF];
    }

    // 将数字转为16进制（小写）
    static inline char ToHexLower(unsigned int value)
    {
        return "0123456789abcdef"[value & 0xF];
    }

    // 将数16进（大写或小写）制转为数字
    static inline int FromHex(unsigned int c)
    {
        return ((c >= '0') && (c <= '9')) ? int(c - '0') :
               ((c >= 'A') && (c <= 'F')) ? int(c - 'A' + 10) :
               ((c >= 'a') && (c <= 'f')) ? int(c - 'a' + 10) :
               /* otherwise */              -1;
    }

    // Hex 16进制编码
    static std::string HexEncode(const std::string& d);

    // Hex 16进制解码
    static std::string HexDecode(const std::string& d);

    // 将int类型（4字节）数据进行Hex编码
    static std::string HexEncode(const unsigned int num);

    // 将8位16进制  解码成unsigned int
    static unsigned int HexDecodeToInt(const std::string& s);
};


#endif //ETHEREUMEXERCISE_HEX_H
