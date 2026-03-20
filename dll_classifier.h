#pragma once

#include <string>

// 判断DLL是否为系统核心DLL
bool IsSystemCoreDLL(const std::string &dllName);

// 检查是否为 C++ 运行库 DLL
bool IsCppRuntimeDLL(const std::string &dllName);

// 判断DLL路径是否位于系统核心目录
bool IsSystemDirectory(const std::string &dllPath);
