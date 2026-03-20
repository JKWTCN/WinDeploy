#include "dll_analyzer.h"
#include "dll_classifier.h"
#include "dll_finder.h"
#include "raii_wrappers.h"
#include "console_utils.h"
#include <windows.h>
#include <dbghelp.h>
#include <iostream>
#include <set>
#include <algorithm>
#include <filesystem>

#pragma comment(lib, "dbghelp.lib")

// 全局集合，用于跟踪已处理的DLL，避免重复和循环依赖
// Windows PE 导入表中的 DLL 名称大小写不固定，使用不区分大小写的比较器防止重复处理
struct CaseInsensitiveCompare
{
    bool operator()(const std::string &a, const std::string &b) const
    {
        return _stricmp(a.c_str(), b.c_str()) < 0;
    }
};

std::set<std::string, CaseInsensitiveCompare> processedDLLs;
std::set<std::string, CaseInsensitiveCompare> globalDLLSet;

// 全局变量：最大递归深度
int g_maxRecursionDepth = 20;

// 设置最大递归深度
void SetMaxRecursionDepth(int depth)
{
    g_maxRecursionDepth = depth;
}

// 获取最大递归深度
int GetMaxRecursionDepth()
{
    return g_maxRecursionDepth;
}

// 将RVA转换为文件偏移量
static DWORD RvaToFileOffset(PIMAGE_NT_HEADERS ntHeaders, DWORD rva)
{
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
    {
        if (rva >= section[i].VirtualAddress &&
            rva < section[i].VirtualAddress + section[i].Misc.VirtualSize)
        {
            return rva - section[i].VirtualAddress + section[i].PointerToRawData;
        }
    }
    return 0; // 未找到
}

// 递归获取DLL依赖
static void GetRecursiveDependentDLLs(const std::string &dllPath, const std::string &exeDir, int depth,
                                      const std::vector<std::string> &extraDirs, PEArchitecture targetArch)
{
    if (depth > g_maxRecursionDepth)
    {
        std::cout << std::string(depth * 2, ' ') << "Warning: Maximum recursion depth (" << g_maxRecursionDepth << ") reached, stopping further analysis" << std::endl;
        return;
    }

    std::string dllName = std::filesystem::path(dllPath).filename().string();

    // 检查是否已处理过这个DLL
    if (processedDLLs.find(dllPath) != processedDLLs.end())
    {
        std::cout << std::string(depth * 2, ' ') << "Info: Already processed: " << dllName << std::endl;
        return;
    }

    // ✓ 在解析依赖之前判断当前DLL的类型
    bool isSystemDLL = IsSystemCoreDLL(dllName);
    bool isCppRuntime = IsCppRuntimeDLL(dllName);

    // 标记为已处理
    processedDLLs.insert(dllPath);

    if (isSystemDLL)
    {
        // 系统 DLL：视而不见（不分析、不拷贝）
        std::cout << std::string(depth * 2, ' ') << "[System DLL] Ignored: " << dllName << std::endl;
        return;  // 不添加到集合，不解析依赖，直接返回
    }

    if (isCppRuntime)
    {
        // C++ 运行库：只拿文件，不问祖宗（拷贝，不递归）
        std::cout << std::string(depth * 2, ' ') << "[C++ Runtime] Copy only, no recursion: " << dllName << std::endl;
        globalDLLSet.insert(dllName);  // 添加到集合以便拷贝
        return;  // 不解析依赖
    }

    // 自己的 DLL：追根溯源（拷贝并递归）
    std::cout << std::string(depth * 2, ' ') << "Analyzing: " << dllName << " (depth: " << depth << ")" << std::endl;
    globalDLLSet.insert(dllName);

    // ✓ 只对需要递归的 DLL 解析依赖
    std::vector<std::string> dependencies = ParseFileDependencies(dllPath.c_str());

    // 递归处理每个依赖
    for (const auto &depName : dependencies)
    {
        // 检查是否为系统核心DLL - 视而不见（不分析、不拷贝）
        if (IsSystemCoreDLL(depName))
        {
            std::cout << std::string((depth + 1) * 2, ' ') << "[System DLL] Ignored: " << depName << std::endl;
            // 系统DLL不添加到集合，不递归分析
            continue;
        }

        // 检查是否为C++运行库 - 只拿文件，不问祖宗（拷贝，不递归）
        if (IsCppRuntimeDLL(depName))
        {
            std::cout << std::string((depth + 1) * 2, ' ') << "[C++ Runtime] Copy only, no recursion: " << depName << std::endl;
            // 添加到集合中以便拷贝，但不递归分析其依赖
            globalDLLSet.insert(depName);
            continue;
        }

        // 查找依赖的DLL（用于验证存在性和递归分析）
        std::string depPath = FindDLLFile(depName, exeDir, extraDirs, targetArch);
        if (depPath.empty())
        {
            std::cerr << std::string((depth + 1) * 2, ' ') << "Warning: Unable to find: " << depName << std::endl;
            // 即使找不到也添加到集合中（使用DLL名称）
            globalDLLSet.insert(depName);
            continue;
        }

        // 添加到全局集合（使用DLL名称，而不是路径）
        // 这样在复制阶段会重新查找架构匹配的DLL
        globalDLLSet.insert(depName);

        // 递归分析这个DLL的依赖 - 追根溯源（拷贝并递归）
        GetRecursiveDependentDLLs(depPath, exeDir, depth + 1, extraDirs, targetArch);
    }
}

// 内部函数：解析单个文件的依赖（不递归）
std::vector<std::string> ParseFileDependencies(const char *filePath)
{
    std::vector<std::string> dllList;

    std::cout << "Analyzing file: " << filePath << std::endl;

    HandleGuard hFile(CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ,
                                  NULL, OPEN_EXISTING, 0, NULL));
    if (hFile == INVALID_HANDLE_VALUE)
    {
        std::cerr << "Error: Unable to open file (Error code: " << GetLastError() << ")" << std::endl;
        return dllList;
    }

    HandleGuard hMap(CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL));
    if (!hMap)
    {
        std::cerr << "Error: Unable to create file mapping (Error code: " << GetLastError() << ")" << std::endl;
        return dllList;
    }

    MappedViewGuard baseAddress(MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0));
    if (!baseAddress)
    {
        std::cerr << "Error: Unable to map file view (Error code: " << GetLastError() << ")" << std::endl;
        return dllList;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)(LPVOID)baseAddress;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        std::cerr << "Error: Invalid DOS signature" << std::endl;
        return dllList;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE *)(LPVOID)baseAddress + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        std::cerr << "Error: Invalid NT signature" << std::endl;
        return dllList;
    }

    // 检查PE文件架构
    if (ntHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 &&
        ntHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
    {
        std::cerr << "Warning: Unsupported PE file architecture: 0x" << std::hex << ntHeaders->FileHeader.Machine << std::endl;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE)
    {
        std::cerr << "Error: Unable to get file size" << std::endl;
        return dllList;
    }

    // 使用set来去重
    std::set<std::string> dllSet;

    // 处理常规导入表
    auto &importDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.VirtualAddress != 0 && importDir.Size != 0)
    {
        std::cout << "\n=== Parsing Regular Import Table ===" << std::endl;

        // 将RVA转换为文件偏移量
        DWORD importDirOffset = RvaToFileOffset(ntHeaders, importDir.VirtualAddress);
        if (importDirOffset == 0)
        {
            std::cerr << "Warning: Unable to convert import table RVA to file offset, skipping import table" << std::endl;
        }
        else
        {

            PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE *)(LPVOID)baseAddress + importDirOffset);
            size_t importTableSize = importDir.Size;
            size_t maxDescriptorCount = importTableSize / sizeof(IMAGE_IMPORT_DESCRIPTOR);

            const size_t MAX_DLL_NAME_LEN = 256;
            std::cout << "Starting to scan import table, up to " << maxDescriptorCount << " entries..." << std::endl;

            for (size_t i = 0; i < maxDescriptorCount; ++i)
            {
                if (importDescriptor[i].Name == 0)
                    break;

                // 将DLL名称RVA转换为文件偏移量
                DWORD nameOffset = RvaToFileOffset(ntHeaders, importDescriptor[i].Name);
                if (nameOffset == 0)
                {
                    std::cerr << "Warning: Skipping invalid DLL name RVA: 0x" << std::hex << importDescriptor[i].Name << std::endl;
                    continue;
                }

                const BYTE *dllNameAddr = (BYTE *)(LPVOID)baseAddress + nameOffset;
                if (dllNameAddr < (BYTE *)(LPVOID)baseAddress || dllNameAddr >= ((BYTE *)(LPVOID)baseAddress + fileSize))
                {
                    std::cerr << "Warning: Skipping out-of-bounds DLL name address" << std::endl;
                    continue;
                }

                // 检查字符串长度和结尾
                size_t len = strnlen((const char *)dllNameAddr, MAX_DLL_NAME_LEN);
                if (len == MAX_DLL_NAME_LEN || dllNameAddr + len >= ((BYTE *)(LPVOID)baseAddress + fileSize))
                {
                    std::cerr << "Warning: Skipping invalid or out-of-bounds DLL name string" << std::endl;
                    continue;
                }

                std::string dllName((const char *)dllNameAddr, len);
                dllSet.insert(dllName);
                std::cout << "Found DLL: " << dllName << std::endl;
            }

            std::cout << "Completed scanning regular import table, found " << dllSet.size() << " dependent DLLs" << std::endl;
        } // else importDirOffset != 0
    }
    else
    {
        std::cout << "Info: File has no regular import table" << std::endl;
    }

    // 处理延迟加载导入表
    std::cout << "\n=== Parsing Delay Load Import Table ===" << std::endl;
    auto delayLoadDLLs = GetDelayLoadDLLs(ntHeaders, (LPVOID)baseAddress, fileSize);
    for (const auto &dll : delayLoadDLLs)
    {
        dllSet.insert(dll);
    }

    // 将set转换为vector
    dllList.assign(dllSet.begin(), dllSet.end());

    std::cout << "\nTotal found " << dllList.size() << " dependent DLL(s) (after deduplication)" << std::endl;
    return dllList;
}

// 公共接口：获取依赖DLL（支持递归）
std::vector<std::string> GetDependentDLLs(const char *executablePath, bool recursive,
                                          const std::vector<std::string> &extraDirs, PEArchitecture targetArch)
{
    if (recursive)
    {
        // 清空全局集合
        processedDLLs.clear();
        globalDLLSet.clear();

        std::cout << "\n=== Starting Recursive Dependency Analysis ===" << std::endl;

        std::string exeDir = std::filesystem::path(executablePath).parent_path().string();

        // 开始递归分析
        GetRecursiveDependentDLLs(executablePath, exeDir, 0, extraDirs, targetArch);

        std::cout << "\n=== Recursive Analysis Complete ===" << std::endl;
        std::cout << "Total " << globalDLLSet.size() << " unique DLL(s) found (including all levels)" << std::endl;

        // 转换为vector
        return std::vector<std::string>(globalDLLSet.begin(), globalDLLSet.end());
    }
    else
    {
        // 非递归模式，只分析第一层
        return ParseFileDependencies(executablePath);
    }
}
