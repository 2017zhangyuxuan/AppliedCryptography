#include "test.h"
#include "sm4.h"
#include <iostream>
#include <string>

using namespace std;

int main(int argc, char *argv[]) {
    /**
     *  测试命令
     *  ./AppliedCryptography -enc -mode cbc -png -in logo.png -out test.png -iv 123456 -key 123456
     *  ./AppliedCryptography -dec -mode cbc -png -in test.png -out dec_test.png -iv 123456 -key 123456
     *
     *  ./AppliedCryptography -enc -mode ecb -in test.txt -out ecb_test.txt -iv 123456 -key 123456
     *  ./AppliedCryptography -dec -mode ecb -in ecb_test.txt -out dec_test.txt -iv 123456 -key 123456
     *
     */

    bool isTest = false;        // 是否执行测试
    bool isEncrypt = false;     // 是否加密
    bool isDectypt = false;     // 是否解密
    bool isPNG = false;         // 指定是否为PNG格式文件
    int mode = 0;               // 加密/解密 模式  0-ECB，1-CBC
    string inputPath = "";      // 输入文件
    string outputPath = "";     // 输出文件
    string IV = "123456";       // IV向量
    string key = "123456";      // key密钥

    // 解析参数
    for (int i = 1; i < argc; i++) {
        string arg(argv[i]);
        if (arg == "-enc") {
            isEncrypt = true;
        } else if (arg == "-dec"){
            isDectypt = true;
        } else if (arg == "-mode") {
            string tmp(argv[++i]);
            if (tmp == "cbc") {
                mode = 1;
            } else if (tmp == "ecb") {
                mode = 0;
            } else {
                cout << "加密模式请输入小写cbc或者ecb" << endl;
            }
        } else if (arg == "-png") {
            isPNG = true;
        } else if (arg == "-in") {
            inputPath = string(argv[++i]);
        } else if (arg == "-out") {
            outputPath = string(argv[++i]);
        } else if (arg == "-test") {
            isTest = true;
        } else if (arg == "-iv") {
            IV = string(argv[++i]);
        } else if ( arg == "-key") {
            key = string(argv[++i]);
        }
    }

    if (isTest) {
        // 执行测试
        Test::TestAll();
    } else if (inputPath.empty() || outputPath.empty()) {
        cout << "请指定输入和输出路径（请使用相对路径）" << endl;
    } else {
        SM4 sm4;
        sm4.GenerateKeys(key, sm4.keys);
        sm4.GenerateRK();
        sm4.GenerateKeys(IV, sm4.IV);

        if (isPNG) {
            if (isEncrypt) {
                sm4.EncPNG(inputPath, outputPath, mode);
            } else {
                sm4.DecPNG(inputPath, outputPath, mode);
            }
        } else {
            if (isEncrypt) {
                sm4.EncFile(inputPath, outputPath, mode);
            } else {
                sm4.DecFile(inputPath,outputPath,mode);
            }
        }
    }


    return 0;
}
