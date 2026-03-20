#pragma once

#include <string>
#include <vector>
#include <windows.h>

// PE文件架构类型枚举
enum class PEArchitecture
{
    Unknown,
    x86,  // 32-bit (IMAGE_FILE_MACHINE_I386)
    x64,  // 64-bit (IMAGE_FILE_MACHINE_AMD64)
    ARM,  // ARM
    ARM64 // ARM64
};

// 将架构转换为字符串
std::string ArchitectureToString(PEArchitecture arch);

// 检查两个架构是否兼容
bool AreArchitecturesCompatible(PEArchitecture arch1, PEArchitecture arch2);

// 检测PE文件的架构
PEArchitecture DetectPEArchitecture(const std::string &filePath);

// 从PE文件中解析延迟加载导入表
std::vector<std::string> GetDelayLoadDLLs(void *ntHeaders, void *baseAddress, DWORD fileSize);
