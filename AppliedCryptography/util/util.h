//
// Created by 张宇轩 on 2021/11/3.
//

#ifndef APPLIEDCRYPTOGRAPHY_UTIL_H
#define APPLIEDCRYPTOGRAPHY_UTIL_H


#include <string>

typedef unsigned char byte;             // 一个字节
typedef unsigned short word16;          // 用short 来表示16位的字
typedef unsigned int word32;            // 用int 来表示32位的字


// 循环左移，参考CryptoPP库里的实现
template <class T> inline T rotlFixed(T x, unsigned int y) {
    unsigned int thisSize = sizeof(T)*8;
    unsigned int mask = thisSize - 1;
    return T((x<<y)|(x>>(-y&mask)));
}

// 循环右移
template <class T> inline T rotrFixed(T x, unsigned int y) {
    unsigned int thisSize = sizeof(T)*8;
    unsigned int mask = thisSize - 1;
    return T((x>>y)|(x<<(-y&mask)));
}


class Util {
    public:
        // 打印输出文件内容
        static void printFile(std::string path);
        // 以Hex编码 打印输出文件内容
        static void printFileWithHex(std::string path);

        // 对输入的message 128bits 跟 IV 进行异或
        static void XOR(word32 message[4], const word32 iv[4]);
        // 对4字节转换成字节序
        static word32 changeByteOrder(word32 message);
        // 转换字节序
        static void changeByteOrder(word32 *message, int size);

        // 比较两个char数组 是否相等
        static bool equalChars(char* src, char* target,int size);

        // 求某个文件的大小
        static int getFileSize(std::fstream& in);
};


#endif //APPLIEDCRYPTOGRAPHY_UTIL_H
