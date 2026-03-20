#include "dll_finder.h"
#include "pe_parser.h"
#include "console_utils.h"
#include "system_info.h"
#include <windows.h>
#include <shlwapi.h>
#include <iostream>
#include <filesystem>

#pragma comment(lib, "shlwapi.lib")

// 搜索DLL文件（支持架构感知查找）
std::string FindDLLFile(const std::string &dllName, const std::string &exeDir,
                        const std::vector<std::string> &extraDirs, PEArchitecture targetArch)
{
    // 首先在额外指定的目录中查找（最高优先级）
    for (const auto &dir : extraDirs)
    {
        std::string dllPath = (std::filesystem::path(dir) / dllName).string();
        if (PathFileExistsA(dllPath.c_str()))
        {
            if (targetArch == PEArchitecture::Unknown)
            {
                // 如果没有指定目标架构，直接返回第一个找到的文件
                return dllPath;
            }

            // 检查架构
            PEArchitecture dllArch = DetectPEArchitecture(dllPath);
            if (AreArchitecturesCompatible(dllArch, targetArch))
            {
                ConsoleColors::Print(ConsoleColors::GREEN, "  Found: ");
                std::cout << dllPath << " → Checking architecture → ";
                ConsoleColors::Print(ConsoleColors::BRIGHT_GREEN, ArchitectureToString(dllArch));
                ConsoleColors::PrintLn(ConsoleColors::GREEN, " ✓ Match");
                return dllPath;
            }
            else
            {
                ConsoleColors::Print(ConsoleColors::YELLOW, "  Found: ");
                std::cout << dllPath << " → Checking architecture → ";
                ConsoleColors::Print(ConsoleColors::BRIGHT_YELLOW, ArchitectureToString(dllArch));
                ConsoleColors::Print(ConsoleColors::YELLOW, " ✗ Mismatch");
                std::cout << " (target: " << ArchitectureToString(targetArch) << "), continuing search" << std::endl;
            }
        }
    }

    // 在可执行文件目录中查找
    std::string dllPath = (std::filesystem::path(exeDir) / dllName).string();
    if (PathFileExistsA(dllPath.c_str()))
    {
        if (targetArch == PEArchitecture::Unknown)
        {
            return dllPath;
        }

        // 检查架构
        PEArchitecture dllArch = DetectPEArchitecture(dllPath);
        if (AreArchitecturesCompatible(dllArch, targetArch))
        {
            ConsoleColors::Print(ConsoleColors::GREEN, "  Found: ");
            std::cout << dllPath << " → Checking architecture → ";
            ConsoleColors::Print(ConsoleColors::BRIGHT_GREEN, ArchitectureToString(dllArch));
            ConsoleColors::PrintLn(ConsoleColors::GREEN, " ✓ Match");
            return dllPath;
        }
        else
        {
            ConsoleColors::Print(ConsoleColors::YELLOW, "  Found: ");
            std::cout << dllPath << " → Checking architecture → ";
            ConsoleColors::Print(ConsoleColors::BRIGHT_YELLOW, ArchitectureToString(dllArch));
            ConsoleColors::Print(ConsoleColors::YELLOW, " ✗ Mismatch");
            std::cout << " (target: " << ArchitectureToString(targetArch) << "), continuing search" << std::endl;
        }
    }

    // 在当前工作目录中查找
    char currentDir[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, currentDir);
    dllPath = (std::filesystem::path(currentDir) / dllName).string();
    if (PathFileExistsA(dllPath.c_str()))
    {
        if (targetArch == PEArchitecture::Unknown)
        {
            return dllPath;
        }

        // 检查架构
        PEArchitecture dllArch = DetectPEArchitecture(dllPath);
        if (AreArchitecturesCompatible(dllArch, targetArch))
        {
            ConsoleColors::Print(ConsoleColors::GREEN, "  Found: ");
            std::cout << dllPath << " → Checking architecture → ";
            ConsoleColors::Print(ConsoleColors::BRIGHT_GREEN, ArchitectureToString(dllArch));
            ConsoleColors::PrintLn(ConsoleColors::GREEN, " ✓ Match");
            return dllPath;
        }
        else
        {
            ConsoleColors::Print(ConsoleColors::YELLOW, "  Found: ");
            std::cout << dllPath << " → Checking architecture → ";
            ConsoleColors::Print(ConsoleColors::BRIGHT_YELLOW, ArchitectureToString(dllArch));
            ConsoleColors::Print(ConsoleColors::YELLOW, " ✗ Mismatch");
            std::cout << " (target: " << ArchitectureToString(targetArch) << "), continuing search" << std::endl;
        }
    }

    // 在系统目录中查找
    dllPath = (std::filesystem::path(GetSystemDirPath()) / dllName).string();
    if (PathFileExistsA(dllPath.c_str()))
    {
        if (targetArch == PEArchitecture::Unknown)
        {
            return dllPath;
        }

        // 检查架构
        PEArchitecture dllArch = DetectPEArchitecture(dllPath);
        if (AreArchitecturesCompatible(dllArch, targetArch))
        {
            ConsoleColors::Print(ConsoleColors::GREEN, "  Found: ");
            std::cout << dllPath << " → Checking architecture → ";
            ConsoleColors::Print(ConsoleColors::BRIGHT_GREEN, ArchitectureToString(dllArch));
            ConsoleColors::PrintLn(ConsoleColors::GREEN, " ✓ Match");
            return dllPath;
        }
        else
        {
            ConsoleColors::Print(ConsoleColors::YELLOW, "  Found: ");
            std::cout << dllPath << " → Checking architecture → ";
            ConsoleColors::Print(ConsoleColors::BRIGHT_YELLOW, ArchitectureToString(dllArch));
            ConsoleColors::Print(ConsoleColors::YELLOW, " ✗ Mismatch");
            std::cout << " (target: " << ArchitectureToString(targetArch) << "), continuing search" << std::endl;
        }
    }

    // 在Windows目录中查找
    dllPath = (std::filesystem::path(GetWindowsDirPath()) / dllName).string();
    if (PathFileExistsA(dllPath.c_str()))
    {
        if (targetArch == PEArchitecture::Unknown)
        {
            return dllPath;
        }

        // 检查架构
        PEArchitecture dllArch = DetectPEArchitecture(dllPath);
        if (AreArchitecturesCompatible(dllArch, targetArch))
        {
            ConsoleColors::Print(ConsoleColors::GREEN, "  Found: ");
            std::cout << dllPath << " → Checking architecture → ";
            ConsoleColors::Print(ConsoleColors::BRIGHT_GREEN, ArchitectureToString(dllArch));
            ConsoleColors::PrintLn(ConsoleColors::GREEN, " ✓ Match");
            return dllPath;
        }
        else
        {
            ConsoleColors::Print(ConsoleColors::YELLOW, "  Found: ");
            std::cout << dllPath << " → Checking architecture → ";
            ConsoleColors::Print(ConsoleColors::BRIGHT_YELLOW, ArchitectureToString(dllArch));
            ConsoleColors::Print(ConsoleColors::YELLOW, " ✗ Mismatch");
            std::cout << " (target: " << ArchitectureToString(targetArch) << "), continuing search" << std::endl;
        }
    }

    // 在PATH环境变量指定的目录中查找
    auto pathDirs = GetPathDirectories();
    for (const auto &dir : pathDirs)
    {
        dllPath = (std::filesystem::path(dir) / dllName).string();
        if (PathFileExistsA(dllPath.c_str()))
        {
            if (targetArch == PEArchitecture::Unknown)
            {
                return dllPath;
            }

            // 检查架构
            PEArchitecture dllArch = DetectPEArchitecture(dllPath);
            if (AreArchitecturesCompatible(dllArch, targetArch))
            {
                ConsoleColors::Print(ConsoleColors::GREEN, "  Found: ");
                std::cout << dllPath << " → Checking architecture → ";
                ConsoleColors::Print(ConsoleColors::BRIGHT_GREEN, ArchitectureToString(dllArch));
                ConsoleColors::PrintLn(ConsoleColors::GREEN, " ✓ Match");
                return dllPath;
            }
            else
            {
                ConsoleColors::Print(ConsoleColors::YELLOW, "  Found: ");
                std::cout << dllPath << " → Checking architecture → ";
                ConsoleColors::Print(ConsoleColors::BRIGHT_YELLOW, ArchitectureToString(dllArch));
                ConsoleColors::Print(ConsoleColors::YELLOW, " ✗ Mismatch");
                std::cout << " (target: " << ArchitectureToString(targetArch) << "), continuing search" << std::endl;
            }
        }
    }

    // 未找到匹配的架构
    return ""; // 未找到
}
