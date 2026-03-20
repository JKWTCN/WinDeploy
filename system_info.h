#pragma once

#include <string>
#include <vector>
#include <set>

// 获取系统目录路径
std::string GetSystemDirPath();

// 获取Windows目录路径
std::string GetWindowsDirPath();

// 获取环境变量PATH中的目录列表
std::vector<std::string> GetPathDirectories();

// 从系统读取 KnownDLLs 列表
std::set<std::string> GetKnownDllsFromSystem(bool isWow64);

// 从 PEB 获取 API Set Namespace
void* GetApiSetNamespace();

// 将 API Set 名称解析为物理 DLL 名称
std::string ResolveApiSetToDll(const std::string& apiSetName);
