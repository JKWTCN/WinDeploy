#pragma once

#include <string>
#include <vector>
#include "pe_parser.h"

// 搜索DLL文件（支持架构感知查找）
std::string FindDLLFile(const std::string &dllName, const std::string &exeDir,
                        const std::vector<std::string> &extraDirs = {},
                        PEArchitecture targetArch = PEArchitecture::Unknown);
