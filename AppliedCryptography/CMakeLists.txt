cmake_minimum_required(VERSION 3.20)
project(AppliedCryptography)

set(CMAKE_CXX_STANDARD 14)

## 设置 可执行程序输出目录
set(output_bin  ${PROJECT_SOURCE_DIR}/build/output/bin)
## 设置库文件输出目录
set(output_lib  ${PROJECT_SOURCE_DIR}/build/output/lib)
## 指定可执行程序输出目录
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${output_bin})
## 指定 库文件输出目录
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${output_lib})

include_directories(FirstWork)
include_directories(util)
include_directories(hash-library)

add_subdirectory(FirstWork)
add_subdirectory(util)
add_subdirectory(hash-library)

add_executable(AppliedCryptography main.cpp)

target_link_libraries(AppliedCryptography FIRSTWORK_LIB)
target_link_libraries(AppliedCryptography UTIL_LIB)
target_link_libraries(AppliedCryptography HASH_LIB)
