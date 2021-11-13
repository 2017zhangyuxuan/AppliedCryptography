//
// Created by 张宇轩 on 2021/11/3.
//

#include "util.h"
#include "hex.h"
#include <fstream>
#include <iostream>

using namespace std;

// 打印输出文件内容
void Util::printFile(std::string path) {
    fstream in;
    in.open(path, ios::in);
    if (in.is_open()) {
        char buffer[1024];
        int cnt = 0;
        do {
            memset(buffer, 0, sizeof(buffer));
            in.read(buffer, 1024);
            cnt = in.gcount();
            cout << buffer << endl;

        } while (cnt >= 1024);
        in.close();
    } else {
        cout << "文件打开失败!" << endl;
    }

}

// 以Hex编码 打印输出文件内容
void Util::printFileWithHex(std::string path) {
    fstream in;
    in.open(path, ios::in);
    if (in.is_open()) {
        char buffer[1024];
        int cnt = 0;
        do {
            memset(buffer, 0, sizeof(buffer));
            in.read(buffer, 1024);
            cnt = in.gcount();

            std::string tmp;
            tmp.resize(1);
            for (int i = 0; i < cnt; i++) {
                tmp[0] = buffer[i];
                cout << Hex::HexEncode(tmp);
            }

        } while (cnt >= 1024);
        in.close();
    } else {
        cout << "文件打开失败!" << endl;
    }
}

// 对输入的message 128bits 跟 IV 进行异或
void Util::XOR(word32 message[4], const word32 iv[4]) {
    for (int i=0;i<4;i++) {
        message[i] = message[i] ^ iv[i];
    }
}

// 对4字节转换成字节序
word32 Util::changeByteOrder(word32 word) {
    byte bytes[4];
    for (int i = 0; i < 4; i++) {
        bytes[i] = (word >> (3 - i) * 8) & 0xff;
    }
    return (bytes[3] << 24) | (bytes[2] << 16) | (bytes[1] << 8) | bytes[0];
}

// 转换字节序
void Util::changeByteOrder(word32 *message, int size) {
    for (int i=0; i<size ;i++){
        message[i] = changeByteOrder(message[i]);
    }
}

// 比较两个char数组 是否相等
bool Util::equalChars(char* src, char* target,int size) {
    for (int i=0;i<size;i++) {
        if (src[i]!=target[i]) {
            return false;
        }
    }
    return true;
}
// 求某个文件的大小
int Util::getFileSize(std::fstream& in) {
    int cur = in.tellg();
    in.seekg(0, ios::end);
    int size = in.tellg();
    in.seekg(cur);
    return size;
}