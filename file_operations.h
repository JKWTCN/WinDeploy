#pragma once

#include <string>
#include <vector>
#include "pe_parser.h"

// 复制文件
bool CopyFileToDirectory(const std::string &sourcePath, const std::string &destDir);

// 复制所有依赖的DLL
bool CopyDependentDLLs(const std::vector<std::string> &dllList, const std::string &exePath,
                       const std::string &destDir, const std::vector<std::string> &extraDirs = {},
                       bool copyAll = false, PEArchitecture targetArch = PEArchitecture::Unknown);
