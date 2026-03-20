#pragma once

#include <string>
#include <vector>
#include <set>

// 从文件中读取额外的搜索目录
std::vector<std::string> LoadExtraSearchDirectories(const std::string &filePath);

// 从文件中读取要忽略的 DLL 列表
void LoadIgnoredDLLs(const std::string &filePath);

// 检查 DLL 是否应该被忽略
bool ShouldIgnoreDLL(const std::string &dllName, const std::string &dllPath);

// 获取全局忽略的 DLL 名称列表
const std::set<std::string>& GetIgnoredDLLNames();

// 获取全局忽略的 DLL 路径列表
const std::set<std::string>& GetIgnoredDLLPaths();

// 获取全局忽略的目录列表
const std::set<std::string>& GetIgnoredDirectories();
