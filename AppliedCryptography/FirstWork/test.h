//
// Created by 张宇轩 on 2021/11/3.
//

#ifndef APPLIEDCRYPTOGRAPHY_TEST_H
#define APPLIEDCRYPTOGRAPHY_TEST_H


class Test {
public:

    static void TestAll();                     // 进行所有测试
    static void TestEncDec();                  // 测试SM4 单次加解密128bits
    static void TestEncDecFileECB();           // 测试SM4 加密和解密文件 ECB模式
    static void TestEncDecFileCBC();           // 测试SM4 加密和解密文件 CBC模式
    static void TestEncDecPNG();               // 测试SM4 加密和解密PNG图片

};


#endif //APPLIEDCRYPTOGRAPHY_TEST_H
