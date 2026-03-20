#include "file_operations.h"
#include "dll_finder.h"
#include "dll_classifier.h"
#include "console_utils.h"
#include "config_loader.h"
#include "system_info.h"
#include "pe_parser.h"
#include <windows.h>
#include <shlwapi.h>
#include <iostream>
#include <filesystem>

#pragma comment(lib, "shlwapi.lib")

// 复制文件
bool CopyFileToDirectory(const std::string &sourcePath, const std::string &destDir)
{
    if (sourcePath.empty() || destDir.empty())
    {
        return false;
    }

    // 确保目标目录存在
    if (!CreateDirectoryA(destDir.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS)
    {
        std::cerr << "Error: Unable to create target directory " << destDir << " (Error code: " << GetLastError() << ")" << std::endl;
        return false;
    }

    // 构造目标文件路径
    std::string fileName = std::filesystem::path(sourcePath).filename().string();
    std::string destPath = (std::filesystem::path(destDir) / fileName).string();

    // 检查目标文件是否已存在
    if (PathFileExistsA(destPath.c_str()))
    {
        std::cout << "Warning: File already exists, skipping copy: " << fileName << std::endl;
        return true;
    }

    // 复制文件
    if (CopyFileA(sourcePath.c_str(), destPath.c_str(), TRUE))
    {
        ConsoleColors::Print(ConsoleColors::GREEN, "✓ Successfully copied: ");
        ConsoleColors::PrintLn(ConsoleColors::BRIGHT_CYAN, fileName);
        return true;
    }
    else
    {
        ConsoleColors::Print(ConsoleColors::RED, "✗ Error: Unable to copy file ");
        ConsoleColors::Print(ConsoleColors::BRIGHT_RED, fileName);
        std::cout << " (Error code: " << GetLastError() << ")" << std::endl;
        return false;
    }
}

// 复制所有依赖的DLL
bool CopyDependentDLLs(const std::vector<std::string> &dllList, const std::string &exePath,
                       const std::string &destDir, const std::vector<std::string> &extraDirs,
                       bool copyAll, PEArchitecture targetArch)
{
    if (dllList.empty())
    {
        std::cout << "No DLL files to copy" << std::endl;
        return true;
    }

    // 获取可执行文件所在目录
    std::string exeDir = std::filesystem::path(exePath).parent_path().string();

    std::cout << "\n";
    ConsoleColors::Print(ConsoleColors::CYAN, "Starting to copy DLL files to target directory: ");
    ConsoleColors::PrintLn(ConsoleColors::BRIGHT_CYAN, destDir);
    if (copyAll)
    {
        ConsoleColors::PrintLn(ConsoleColors::YELLOW, "Note: --copy-all flag is set, system core DLLs will NOT be skipped");
    }
    else
    {
        ConsoleColors::PrintLn(ConsoleColors::YELLOW, "Note: System core DLLs (such as KERNEL32.dll, etc.) will be automatically skipped as these are Windows built-in DLLs");
    }

    const auto& ignoredNames = GetIgnoredDLLNames();
    const auto& ignoredPaths = GetIgnoredDLLPaths();
    const auto& ignoredDirs = GetIgnoredDirectories();

    if (!ignoredNames.empty() || !ignoredPaths.empty() || !ignoredDirs.empty())
    {
        std::cout << "Note: ";
        ConsoleColors::PrintLn(ConsoleColors::MAGENTA, std::to_string(ignoredNames.size() + ignoredPaths.size() + ignoredDirs.size()) + " item(s) in ignore list");
    }

    int successCount = 0;
    int failCount = 0;
    int skippedCount = 0;
    int ignoredCount = 0;

    std::vector<std::string> succeededDLLs;
    std::vector<std::string> failedDLLs; // Format: "dllName:reason"

    // Cache PATH directories to avoid repeated parsing inside the loop
    auto pathDirs = GetPathDirectories();

    for (const auto &dllName : dllList)
    {
        ConsoleColors::Print(ConsoleColors::CYAN, "Searching for: ");
        std::cout << dllName << std::endl;

        // 检查是否为系统核心DLL
        if (!copyAll && IsSystemCoreDLL(dllName))
        {
            ConsoleColors::Print(ConsoleColors::YELLOW, "[System Core DLL] Skipped: ");
            std::cout << dllName << " (This is a Windows built-in DLL, no need to copy)" << std::endl;
            skippedCount++;
            continue;
        }

        std::string dllPath = FindDLLFile(dllName, exeDir, extraDirs, targetArch);
        if (dllPath.empty())
        {
            std::string reason;

            // 检查是否有任何搜索位置存在该文件（无论架构是否匹配）
            bool anyFileFound = false;

            // 检查各个搜索位置
            for (const auto &dir : extraDirs)
            {
                std::string testPath = (std::filesystem::path(dir) / dllName).string();
                if (PathFileExistsA(testPath.c_str()))
                {
                    anyFileFound = true;
                    break;
                }
            }

            if (!anyFileFound)
            {
                std::string testPath = (std::filesystem::path(exeDir) / dllName).string();
                if (PathFileExistsA(testPath.c_str()))
                {
                    anyFileFound = true;
                }
            }

            if (!anyFileFound)
            {
                char currentDir[MAX_PATH];
                GetCurrentDirectoryA(MAX_PATH, currentDir);
                std::string testPath = (std::filesystem::path(currentDir) / dllName).string();
                if (PathFileExistsA(testPath.c_str()))
                {
                    anyFileFound = true;
                }
            }

            if (!anyFileFound)
            {
                std::string testPath = (std::filesystem::path(GetSystemDirPath()) / dllName).string();
                if (PathFileExistsA(testPath.c_str()))
                {
                    anyFileFound = true;
                }
            }

            if (!anyFileFound)
            {
                std::string testPath = (std::filesystem::path(GetWindowsDirPath()) / dllName).string();
                if (PathFileExistsA(testPath.c_str()))
                {
                    anyFileFound = true;
                }
            }

            if (!anyFileFound)
            {
                for (const auto &dir : pathDirs)
                {
                    std::string testPath = (std::filesystem::path(dir) / dllName).string();
                    if (PathFileExistsA(testPath.c_str()))
                    {
                        anyFileFound = true;
                        break;
                    }
                }
            }

            // 根据是否找到文件和是否指定架构来决定错误消息
            if (anyFileFound && targetArch != PEArchitecture::Unknown)
            {
                reason = "No matching architecture found (need " + ArchitectureToString(targetArch) + ")";
            }
            else if (!anyFileFound)
            {
                reason = "File not found in any search location";
            }
            else
            {
                reason = "File not found in any search location";
            }

            ConsoleColors::Print(ConsoleColors::RED, "✗ Error: ");
            ConsoleColors::Print(ConsoleColors::BRIGHT_RED, dllName);
            std::cout << " - " << reason << std::endl;
            failCount++;
            failedDLLs.push_back(dllName + ":" + reason);
            continue;
        }

        // 检查 DLL 路径是否位于系统核心目录
        if (!copyAll && IsSystemDirectory(dllPath))
        {
            ConsoleColors::Print(ConsoleColors::YELLOW, "[System Directory] Skipped: ");
            std::cout << dllName << " (Location: " << dllPath << ")" << std::endl;
            std::cout << "  This DLL is in a Windows system directory and will be available on the target system" << std::endl;
            skippedCount++;
            continue;
        }

        // 检查是否在忽略列表中
        if (ShouldIgnoreDLL(dllName, dllPath))
        {
            ConsoleColors::Print(ConsoleColors::MAGENTA, "[Ignored] Skipped: ");
            std::cout << dllName << " (in ignore list)" << std::endl;
            ignoredCount++;
            continue;
        }

        ConsoleColors::Print(ConsoleColors::GREEN, "Found DLL: ");
        std::cout << dllPath << std::endl;

        if (CopyFileToDirectory(dllPath, destDir))
        {
            successCount++;
            succeededDLLs.push_back(dllName + "::" + dllPath);
        }
        else
        {
            failCount++;
            failedDLLs.push_back(dllName + ":Copy failed (see error above)");
        }
    }

    std::cout << "\n";
    ConsoleColors::Print(ConsoleColors::CYAN, "Copy completed: ");
    ConsoleColors::Print(ConsoleColors::GREEN, std::to_string(successCount) + " succeeded");
    std::cout << ", ";
    ConsoleColors::Print(ConsoleColors::RED, std::to_string(failCount) + " failed");
    std::cout << ", ";
    ConsoleColors::Print(ConsoleColors::YELLOW, std::to_string(skippedCount) + " system core DLLs skipped");
    std::cout << ", ";
    ConsoleColors::Print(ConsoleColors::MAGENTA, std::to_string(ignoredCount) + " ignored by user");
    std::cout << std::endl;

    // 如果有成功的 DLL，输出成功列表
    if (!succeededDLLs.empty())
    {
        std::cout << "\n";
        ConsoleColors::PrintLn(ConsoleColors::GREEN, "Successfully copied DLLs:");
        for (const auto &dllInfo : succeededDLLs)
        {
            std::cout << "  ";
            ConsoleColors::Print(ConsoleColors::GREEN, "[OK] ");
            // 分割 DLL 名称和路径（使用 "::" 作为分隔符以避免与 Windows 路径中的 ":" 冲突）
            size_t sepPos = dllInfo.find("::");
            if (sepPos != std::string::npos)
            {
                std::string dllName = dllInfo.substr(0, sepPos);
                std::string path = dllInfo.substr(sepPos + 2);
                ConsoleColors::Print(ConsoleColors::BRIGHT_CYAN, dllName);
                std::cout << ": ";
                ConsoleColors::PrintLn(ConsoleColors::DEFAULT, path);
            }
            else
            {
                ConsoleColors::PrintLn(ConsoleColors::DEFAULT, dllInfo);
            }
        }
    }

    // 如果有失败的 DLL，输出失败列表
    if (!failedDLLs.empty())
    {
        std::cout << "\n";
        ConsoleColors::PrintLn(ConsoleColors::RED, "Failed to copy DLLs:");
        for (const auto &dllInfo : failedDLLs)
        {
            std::cout << "  ";
            ConsoleColors::Print(ConsoleColors::RED, "[FAIL] ");
            // 分割 DLL 名称和原因
            size_t colonPos = dllInfo.find(':');
            if (colonPos != std::string::npos)
            {
                std::string dllName = dllInfo.substr(0, colonPos);
                std::string reason = dllInfo.substr(colonPos + 1);
                ConsoleColors::Print(ConsoleColors::BRIGHT_RED, dllName);
                std::cout << " - ";
                ConsoleColors::PrintLn(ConsoleColors::YELLOW, reason);
            }
            else
            {
                ConsoleColors::PrintLn(ConsoleColors::BRIGHT_RED, dllInfo);
            }
        }
        std::cout << "\n";
        ConsoleColors::PrintLn(ConsoleColors::RED, "Some DLL files failed to copy, please check error messages above");
    }

    return failCount == 0;
}
