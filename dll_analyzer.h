#pragma once

#include <string>
#include <vector>
#include "pe_parser.h"

// 内部函数：解析单个文件的依赖（不递归）
std::vector<std::string> ParseFileDependencies(const char *filePath);

// 公共接口：获取依赖DLL（支持递归）
std::vector<std::string> GetDependentDLLs(const char *executablePath, bool recursive = false,
                                          const std::vector<std::string> &extraDirs = {},
                                          PEArchitecture targetArch = PEArchitecture::Unknown);

// 设置最大递归深度
void SetMaxRecursionDepth(int depth);

// 获取最大递归深度
int GetMaxRecursionDepth();
