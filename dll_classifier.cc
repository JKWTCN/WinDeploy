#include "dll_classifier.h"
#include "system_info.h"
#include <windows.h>
#include <algorithm>
#include <filesystem>

// 系统核心DLL列表
// 注意：C++ 运行库 (MSVCR*.dll, MSVCP*.dll, UCRTBASE.dll, VCRUNTIME*.dll, VCCORLIB*.dll)
// 不在此列表中，需要被复制
const std::set<std::string> systemCoreDLLs = {
    "KERNEL32.dll",
    "KERNEL32.DLL",
    "USER32.dll",
    "USER32.DLL",
    "GDI32.dll",
    "GDI32.DLL",
    "ADVAPI32.dll",
    "ADVAPI32.DLL",
    "SHELL32.dll",
    "SHELL32.DLL",
    "COMCTL32.dll",
    "COMCTL32.DLL",
    "COMDLG32.dll",
    "COMDLG32.DLL",
    "OLE32.dll",
    "OLE32.DLL",
    "OLEAUT32.dll",
    "OLEAUT32.DLL",
    "WS2_32.dll",
    "WS2_32.DLL",
    "WINSPOOL.DRV",
    "WINSPOOL.drv",
    "VERSION.dll",
    "VERSION.DLL",
    "IMM32.dll",
    "IMM32.DLL",
    "WINMM.DLL",
    "WINMM.dll",
    "MSVCRT.DLL",
    "MSVCRT.dll",
    "NTDLL.dll",
    "NTDLL.DLL",
    "CRYPT32.dll",
    "CRYPT32.DLL",
    "RPCRT4.dll",
    "RPCRT4.DLL",
    "SHLWAPI.dll",
    "SHLWAPI.DLL",
};

// 判断DLL是否为系统核心DLL
bool IsSystemCoreDLL(const std::string &dllName)
{
    std::string upperDllName = dllName;
    std::transform(upperDllName.begin(), upperDllName.end(), upperDllName.begin(), ::toupper);

    // 1. 检查 API Sets - 解析到物理 DLL 并判断
    if (upperDllName.find("API-MS-WIN-") == 0 || upperDllName.find("EXT-MS-") == 0) {
        std::string resolvedDll = ResolveApiSetToDll(dllName);
        if (!resolvedDll.empty()) {
            // 如果解析到 C++ 运行时，需要复制
            if (IsCppRuntimeDLL(resolvedDll)) {
                return false;
            }
            // 其他 API Sets 解析到的都是系统 DLL
            return true;
        }
        // 无法解析的 API Set，检查是否为 C++ 运行时相关的 API Set
        if (IsCppRuntimeDLL(dllName)) {
            return false;
        }
        // 无法解析的非 C++ 运行时 API Set 默认为系统 DLL
        return true;
    }

    // 2. 动态检查 KnownDLLs
    BOOL isWow64 = FALSE;
#if defined(_WIN64)
    IsWow64Process(GetCurrentProcess(), &isWow64);
#else
    isWow64 = TRUE;
#endif

    static std::set<std::string> knownDlls = GetKnownDllsFromSystem(isWow64);

    for (const auto& knownDll : knownDlls) {
        std::string upperKnownDll = knownDll;
        std::transform(upperKnownDll.begin(), upperKnownDll.end(), upperKnownDll.begin(), ::toupper);
        if (upperDllName == upperKnownDll) {
            // C++ 运行时需要复制，即使它在 KnownDLLs 中
            if (IsCppRuntimeDLL(dllName)) {
                return false;
            }
            return true;
        }
    }

    // 3. 补充：使用硬编码列表作为后备
    // 即使 GetKnownDllsFromSystem 返回了结果，也检查硬编码列表
    // 因为 KnownDLLs 可能不完整，需要硬编码列表作为补充
    for (const auto &systemDll : systemCoreDLLs) {
        std::string upperSystemDll = systemDll;
        std::transform(upperSystemDll.begin(), upperSystemDll.end(), upperSystemDll.begin(), ::toupper);
        if (upperDllName == upperSystemDll) {
            if (IsCppRuntimeDLL(dllName)) {
                return false;
            }
            return true;
        }
    }

    return false;
}

// 检查是否为 C++ 运行库 DLL
bool IsCppRuntimeDLL(const std::string &dllName)
{
    std::string upperDllName = dllName;
    std::transform(upperDllName.begin(), upperDllName.end(), upperDllName.begin(), ::toupper);

    // 排除 msvcp_win.dll，它是系统内置的
    if (upperDllName == "MSVCP_WIN.DLL") {
        return false;
    }

    // 排除 msvcrt.dll，它是旧版 C 运行时（Windows 自带），应该被视为系统核心 DLL
    if (upperDllName == "MSVCRT.DLL") {
        return false;
    }

    // C 运行库
    if ((upperDllName.find("MSVCR") == 0 || upperDllName.find("VCRUNTIME") == 0) &&
        upperDllName.find(".DLL") == upperDllName.length() - 4) {
        return true;
    }

    // C++ 标准库
    if (upperDllName.find("MSVCP") == 0 && upperDllName.find(".DLL") == upperDllName.length() - 4) {
        return true;
    }

    // C++/CX 库
    if (upperDllName.find("VCCORLIB") == 0 && upperDllName.find(".DLL") == upperDllName.length() - 4) {
        return true;
    }

    // UCRT
    if (upperDllName == "UCRTBASE.DLL") {
        return true;
    }

    // ConcRT
    if (upperDllName.find("CONCRT") == 0 && upperDllName.find(".DLL") == upperDllName.length() - 4) {
        return true;
    }

    // UCRT API Sets
    if (upperDllName.find("API-MS-WIN-CRT-") == 0) {
        return true;
    }

    return false;
}

// 判断DLL路径是否位于系统核心目录
bool IsSystemDirectory(const std::string &dllPath)
{
    if (dllPath.empty())
    {
        return false;
    }

    // 提取 DLL 文件名
    std::string dllName = std::filesystem::path(dllPath).filename().string();

    // 如果是 C++ 运行库，即使位于系统目录也不跳过
    if (IsCppRuntimeDLL(dllName))
    {
        return false;
    }

    // 转换为大写进行路径比较
    std::string upperPath = dllPath;
    std::transform(upperPath.begin(), upperPath.end(), upperPath.begin(), ::toupper);

    // 获取系统核心目录路径
    std::string systemDir = GetSystemDirPath();
    std::string windowsDir = GetWindowsDirPath();

    std::transform(systemDir.begin(), systemDir.end(), systemDir.begin(), ::toupper);
    std::transform(windowsDir.begin(), windowsDir.end(), windowsDir.begin(), ::toupper);

    // 检查是否在 System32 目录中
    if (upperPath.find(systemDir) == 0)
    {
        // 确保后面是路径分隔符或者是完全匹配
        size_t systemDirLen = systemDir.length();
        if (upperPath.length() == systemDirLen ||
            upperPath[systemDirLen] == '\\' ||
            upperPath[systemDirLen] == '/')
        {
            return true;
        }
    }

    // 检查是否在 Windows 目录下（包括 SysWOW64, WinSxS 等）
    if (upperPath.find(windowsDir) == 0)
    {
        // 检查是否为系统核心子目录
        size_t windowsDirLen = windowsDir.length();
        if (upperPath.length() > windowsDirLen &&
            (upperPath[windowsDirLen] == '\\' || upperPath[windowsDirLen] == '/'))
        {
            // 获取 Windows 目录下的子路径
            std::string subPath = upperPath.substr(windowsDirLen + 1);

            // 检查是否为系统核心子目录
            const std::vector<std::string> systemSubDirs = {
                "SYSTEM32",
                "SYSWOW64",
                "WINSXS",
                "GLOBALIZATION"};

            for (const auto &subDir : systemSubDirs)
            {
                if (subPath.find(subDir) == 0)
                {
                    // 确保后面是路径分隔符或者是完全匹配
                    if (subPath.length() == subDir.length() ||
                        subPath[subDir.length()] == '\\' ||
                        subPath[subDir.length()] == '/')
                    {
                        return true;
                    }
                }
            }
        }
    }

    return false;
}
