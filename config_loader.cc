#include "config_loader.h"
#include <windows.h>
#include <shlwapi.h>
#include <iostream>
#include <fstream>
#include <algorithm>

#pragma comment(lib, "shlwapi.lib")

// 全局变量：要忽略的 DLL 名称列表
std::set<std::string> g_ignoredDLLNames;
// 全局变量：要忽略的 DLL 文件路径列表
std::set<std::string> g_ignoredDLLPaths;
// 全局变量：要忽略的文件夹路径列表
std::set<std::string> g_ignoredDirectories;

// 从文件中读取额外的搜索目录
std::vector<std::string> LoadExtraSearchDirectories(const std::string &filePath)
{
    std::vector<std::string> directories;
    std::ifstream file(filePath);

    if (!file.is_open())
    {
        std::cerr << "Warning: Unable to open extra search directories file: " << filePath << std::endl;
        return directories;
    }

    std::cout << "Loading extra search directories from: " << filePath << std::endl;

    std::string line;
    int lineNum = 0;
    while (std::getline(file, line))
    {
        lineNum++;

        // 跳过空行
        if (line.empty())
        {
            continue;
        }

        // 跳过注释行（以#或;开头）
        if (line[0] == '#' || line[0] == ';')
        {
            continue;
        }

        // 去除行首尾的空白字符
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);

        // 再次检查是否为空
        if (line.empty())
        {
            continue;
        }

        // 检查目录是否存在
        if (!PathFileExistsA(line.c_str()))
        {
            std::cerr << "Warning (line " << lineNum << "): Directory does not exist, skipping: " << line << std::endl;
            continue;
        }

        directories.push_back(line);
        std::cout << "  Added: " << line << std::endl;
    }

    file.close();

    std::cout << "Loaded " << directories.size() << " extra search director" << (directories.size() == 1 ? "y" : "ies") << std::endl;

    return directories;
}

// 从文件中读取要忽略的 DLL 列表
void LoadIgnoredDLLs(const std::string &filePath)
{
    std::ifstream file(filePath);

    if (!file.is_open())
    {
        std::cerr << "Warning: Unable to open ignore DLL file: " << filePath << std::endl;
        return;
    }

    std::cout << "Loading ignore list from: " << filePath << std::endl;

    std::string line;
    int lineNum = 0;
    int nameCount = 0, pathCount = 0, dirCount = 0;

    while (std::getline(file, line))
    {
        lineNum++;

        // 跳过空行
        if (line.empty())
        {
            continue;
        }

        // 跳过注释行（以#或;开头）
        if (line[0] == '#' || line[0] == ';')
        {
            continue;
        }

        // 去除行首尾的空白字符
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);

        // 再次检查是否为空
        if (line.empty())
        {
            continue;
        }

        // 检查是否为文件路径（包含 .dll 或 .DLL）
        if (line.find(".dll") != std::string::npos || line.find(".DLL") != std::string::npos)
        {
            // 检查是否为存在的文件
            DWORD attrs = GetFileAttributesA(line.c_str());
            if (attrs != INVALID_FILE_ATTRIBUTES)
            {
                if (attrs & FILE_ATTRIBUTE_DIRECTORY)
                {
                    // 是目录
                    g_ignoredDirectories.insert(line);
                    dirCount++;
                    std::cout << "  Added directory to ignore: " << line << std::endl;
                }
                else
                {
                    // 是文件
                    g_ignoredDLLPaths.insert(line);
                    pathCount++;
                    std::cout << "  Added DLL path to ignore: " << line << std::endl;
                }
            }
            else
            {
                // 文件不存在,可能只是 DLL 名称
                g_ignoredDLLNames.insert(line);
                nameCount++;
                std::cout << "  Added DLL name to ignore: " << line << std::endl;
            }
        }
        else
        {
            // 可能是目录路径(不包含 .dll)
            DWORD attrs = GetFileAttributesA(line.c_str());
            if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY))
            {
                g_ignoredDirectories.insert(line);
                dirCount++;
                std::cout << "  Added directory to ignore: " << line << std::endl;
            }
            else
            {
                // 当作 DLL 名称处理
                g_ignoredDLLNames.insert(line);
                nameCount++;
                std::cout << "  Added DLL name to ignore: " << line << std::endl;
            }
        }
    }

    file.close();

    std::cout << "Loaded " << nameCount << " DLL names, " << pathCount << " DLL paths, and " << dirCount << " director" << (dirCount == 1 ? "y" : "ies") << " to ignore" << std::endl;
}

// 检查 DLL 是否应该被忽略
bool ShouldIgnoreDLL(const std::string &dllName, const std::string &dllPath)
{
    // 检查 DLL 名称
    for (const auto &ignoredName : g_ignoredDLLNames)
    {
        // 不区分大小写比较
        std::string upperDllName = dllName;
        std::string upperIgnoredName = ignoredName;
        std::transform(upperDllName.begin(), upperDllName.end(), upperDllName.begin(), ::toupper);
        std::transform(upperIgnoredName.begin(), upperIgnoredName.end(), upperIgnoredName.begin(), ::toupper);

        if (upperDllName == upperIgnoredName)
        {
            return true;
        }
    }

    // 检查 DLL 文件路径
    for (const auto &ignoredPath : g_ignoredDLLPaths)
    {
        // 不区分大小写比较路径
        if (_stricmp(dllPath.c_str(), ignoredPath.c_str()) == 0)
        {
            return true;
        }
    }

    // 检查是否在忽略的目录中
    for (const auto &ignoredDir : g_ignoredDirectories)
    {
        // 检查 DLL 路径是否以忽略目录开头(不区分大小写)
        size_t dirLen = ignoredDir.length();
        if (dllPath.length() >= dirLen)
        {
            std::string dllPathPrefix = dllPath.substr(0, dirLen);
            if (_stricmp(dllPathPrefix.c_str(), ignoredDir.c_str()) == 0)
            {
                // 确保后面是路径分隔符
                if (dllPath.length() == dirLen || dllPath[dirLen] == '\\' || dllPath[dirLen] == '/')
                {
                    return true;
                }
            }
        }
    }

    return false;
}

// 获取全局忽略的 DLL 名称列表
const std::set<std::string>& GetIgnoredDLLNames()
{
    return g_ignoredDLLNames;
}

// 获取全局忽略的 DLL 路径列表
const std::set<std::string>& GetIgnoredDLLPaths()
{
    return g_ignoredDLLPaths;
}

// 获取全局忽略的目录列表
const std::set<std::string>& GetIgnoredDirectories()
{
    return g_ignoredDirectories;
}
