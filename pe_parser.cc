#include "pe_parser.h"
#include "raii_wrappers.h"
#include <windows.h>
#include <dbghelp.h>
#include <iostream>
#include <algorithm>
#include <cstring>

#pragma comment(lib, "dbghelp.lib")

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

// 将架构转换为字符串
std::string ArchitectureToString(PEArchitecture arch)
{
    switch (arch)
    {
    case PEArchitecture::x86:
        return "x86 (32-bit)";
    case PEArchitecture::x64:
        return "x64 (64-bit)";
    case PEArchitecture::ARM:
        return "ARM (32-bit)";
    case PEArchitecture::ARM64:
        return "ARM64 (64-bit)";
    case PEArchitecture::Unknown:
    default:
        return "Unknown";
    }
}

// 检查两个架构是否兼容
bool AreArchitecturesCompatible(PEArchitecture arch1, PEArchitecture arch2)
{
    // 如果任一架构为Unknown，则认为兼容（保持向后兼容）
    if (arch1 == PEArchitecture::Unknown || arch2 == PEArchitecture::Unknown)
    {
        return true;
    }
    // 架构必须完全匹配
    return arch1 == arch2;
}

// 检测PE文件的架构
PEArchitecture DetectPEArchitecture(const std::string &filePath)
{
    HandleGuard hFile(CreateFileA(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                  NULL, OPEN_EXISTING, 0, NULL));
    if (hFile == INVALID_HANDLE_VALUE)
    {
        return PEArchitecture::Unknown;
    }

    HandleGuard hMap(CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL));
    if (!hMap)
    {
        return PEArchitecture::Unknown;
    }

    MappedViewGuard baseAddress(MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0));
    if (!baseAddress)
    {
        return PEArchitecture::Unknown;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)(LPVOID)baseAddress;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return PEArchitecture::Unknown;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE *)(LPVOID)baseAddress + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        return PEArchitecture::Unknown;
    }

    // 根据Machine字段判断架构
    switch (ntHeaders->FileHeader.Machine)
    {
    case IMAGE_FILE_MACHINE_I386:
        return PEArchitecture::x86;
    case IMAGE_FILE_MACHINE_AMD64:
        return PEArchitecture::x64;
    case IMAGE_FILE_MACHINE_ARM:
        return PEArchitecture::ARM;
    case IMAGE_FILE_MACHINE_ARM64:
        return PEArchitecture::ARM64;
    default:
        return PEArchitecture::Unknown;
    }
}

// 从延迟加载导入表中提取DLL
std::vector<std::string> GetDelayLoadDLLs(void *ntHeaders, void *baseAddress, DWORD fileSize)
{
    std::vector<std::string> dllList;
    auto *ntHdr = static_cast<PIMAGE_NT_HEADERS>(ntHeaders);
    auto *baseAddr = static_cast<LPVOID>(baseAddress);

    // 获取延迟加载导入表
    auto &delayLoadDir = ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
    if (delayLoadDir.VirtualAddress == 0 || delayLoadDir.Size == 0)
    {
        std::cout << "Info: File has no delay load import table" << std::endl;
        return dllList;
    }

    std::cout << "Found delay load import table, starting to parse..." << std::endl;

    // 将RVA转换为文件偏移量
    DWORD delayLoadOffset = RvaToFileOffset(ntHdr, delayLoadDir.VirtualAddress);
    if (delayLoadOffset == 0)
    {
        std::cerr << "Warning: Unable to convert delay load table RVA to file offset" << std::endl;
        return dllList;
    }

    PIMAGE_DELAYLOAD_DESCRIPTOR delayDesc = (PIMAGE_DELAYLOAD_DESCRIPTOR)((BYTE *)baseAddr + delayLoadOffset);
    size_t delayTableSize = delayLoadDir.Size;
    size_t maxDescriptorCount = delayTableSize / sizeof(IMAGE_DELAYLOAD_DESCRIPTOR);

    const size_t MAX_DLL_NAME_LEN = 256;
    std::cout << "Starting to scan delay load table, up to " << maxDescriptorCount << " entries..." << std::endl;

    for (size_t i = 0; i < maxDescriptorCount; ++i)
    {
        // 检查描述符是否有效（所有字段都为0表示结束）
        if (delayDesc[i].Attributes.AllAttributes == 0 &&
            delayDesc[i].DllNameRVA == 0 &&
            delayDesc[i].ModuleHandleRVA == 0 &&
            delayDesc[i].ImportAddressTableRVA == 0 &&
            delayDesc[i].ImportNameTableRVA == 0 &&
            delayDesc[i].BoundImportAddressTableRVA == 0 &&
            delayDesc[i].UnloadInformationTableRVA == 0 &&
            delayDesc[i].TimeDateStamp == 0)
        {
            break;
        }

        if (delayDesc[i].DllNameRVA == 0)
        {
            continue;
        }

        // 将DLL名称RVA转换为文件偏移量
        DWORD nameOffset = RvaToFileOffset(ntHdr, delayDesc[i].DllNameRVA);
        if (nameOffset == 0)
        {
            std::cerr << "Warning: Skipping invalid delay load DLL name RVA: 0x" << std::hex << delayDesc[i].DllNameRVA << std::endl;
            continue;
        }

        const BYTE *dllNameAddr = (BYTE *)baseAddr + nameOffset;
        if (dllNameAddr < (BYTE *)baseAddr || dllNameAddr >= ((BYTE *)baseAddr + fileSize))
        {
            std::cerr << "Warning: Skipping out-of-bounds delay load DLL name address" << std::endl;
            continue;
        }

        // 检查字符串长度和结尾
        size_t len = strnlen((const char *)dllNameAddr, MAX_DLL_NAME_LEN);
        if (len == MAX_DLL_NAME_LEN || dllNameAddr + len >= ((BYTE *)baseAddr + fileSize))
        {
            std::cerr << "Warning: Skipping invalid or out-of-bounds delay load DLL name string" << std::endl;
            continue;
        }

        std::string dllName((const char *)dllNameAddr, len);
        dllList.push_back(dllName);
        std::cout << "Found delay load DLL: " << dllName << std::endl;
    }

    std::cout << "Completed scanning delay load table, found " << dllList.size() << " DLLs" << std::endl;
    return dllList;
}
