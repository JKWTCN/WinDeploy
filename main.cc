#include <windows.h>
#include <dbghelp.h>
#include <iostream>
#include <vector>
#include <string>
#include <memory>
#include <filesystem>
#include <shlwapi.h>
#include <set>
#include <algorithm>
#include <fstream>
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "shlwapi.lib")

// 控制台颜色代码
namespace ConsoleColors
{
    enum Color
    {
        DEFAULT = 7,        // 默认白色
        GREEN = 10,         // 绿色
        RED = 12,           // 红色
        YELLOW = 14,        // 黄色
        BLUE = 9,           // 蓝色
        CYAN = 11,          // 青色
        MAGENTA = 13,       // 洋红色
        BRIGHT_GREEN = 10,  // 亮绿色
        BRIGHT_RED = 12,    // 亮红色
        BRIGHT_YELLOW = 14, // 亮黄色
        BRIGHT_BLUE = 9,    // 亮蓝色
        BRIGHT_CYAN = 11,   // 亮青色
        BRIGHT_MAGENTA = 13 // 亮洋红色
    };

    // 设置控制台文本颜色
    inline void SetColor(Color color)
    {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
    }

    // 重置为默认颜色
    inline void Reset()
    {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), DEFAULT);
    }

    // 带颜色的输出辅助函数
    inline void Print(Color color, const std::string &text)
    {
        SetColor(color);
        std::cout << text;
        Reset();
    }

    inline void PrintLn(Color color, const std::string &text)
    {
        SetColor(color);
        std::cout << text << std::endl;
        Reset();
    }
}

// RAII包装器用于Windows句柄
struct HandleGuard
{
    HANDLE handle;
    HandleGuard(HANDLE h) : handle(h) {}
    ~HandleGuard()
    {
        if (handle != INVALID_HANDLE_VALUE && handle != NULL)
            CloseHandle(handle);
    }
    operator HANDLE() const { return handle; }
};

// RAII包装器用于内存映射视图
struct MappedViewGuard
{
    LPVOID address;
    MappedViewGuard(LPVOID addr) : address(addr) {}
    ~MappedViewGuard()
    {
        if (address)
            UnmapViewOfFile(address);
    }
    operator LPVOID() const { return address; }
};

// 将RVA转换为文件偏移量
DWORD RvaToFileOffset(PIMAGE_NT_HEADERS ntHeaders, DWORD rva)
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

// 从延迟加载导入表中提取DLL
std::vector<std::string> GetDelayLoadDLLs(PIMAGE_NT_HEADERS ntHeaders, LPVOID baseAddress, DWORD fileSize)
{
    std::vector<std::string> dllList;

    // 获取延迟加载导入表
    // 注意：延迟加载表的索引通常是 IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT (值为 13)
    auto &delayLoadDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
    if (delayLoadDir.VirtualAddress == 0 || delayLoadDir.Size == 0)
    {
        std::cout << "Info: File has no delay load import table" << std::endl;
        return dllList;
    }

    std::cout << "Found delay load import table, starting to parse..." << std::endl;

    // 将RVA转换为文件偏移量
    DWORD delayLoadOffset = RvaToFileOffset(ntHeaders, delayLoadDir.VirtualAddress);
    if (delayLoadOffset == 0)
    {
        std::cerr << "Warning: Unable to convert delay load table RVA to file offset" << std::endl;
        return dllList;
    }

    PIMAGE_DELAYLOAD_DESCRIPTOR delayDesc = (PIMAGE_DELAYLOAD_DESCRIPTOR)((BYTE *)baseAddress + delayLoadOffset);
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
        DWORD nameOffset = RvaToFileOffset(ntHeaders, delayDesc[i].DllNameRVA);
        if (nameOffset == 0)
        {
            std::cerr << "Warning: Skipping invalid delay load DLL name RVA: 0x" << std::hex << delayDesc[i].DllNameRVA << std::endl;
            continue;
        }

        const BYTE *dllNameAddr = (BYTE *)baseAddress + nameOffset;
        if (dllNameAddr < (BYTE *)baseAddress || dllNameAddr >= ((BYTE *)baseAddress + fileSize))
        {
            std::cerr << "Warning: Skipping out-of-bounds delay load DLL name address" << std::endl;
            continue;
        }

        // 检查字符串长度和结尾
        size_t len = strnlen((const char *)dllNameAddr, MAX_DLL_NAME_LEN);
        if (len == MAX_DLL_NAME_LEN || dllNameAddr + len >= ((BYTE *)baseAddress + fileSize))
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

// PE文件架构类型枚举
enum class PEArchitecture
{
    Unknown,
    x86,  // 32-bit (IMAGE_FILE_MACHINE_I386)
    x64,  // 64-bit (IMAGE_FILE_MACHINE_AMD64)
    ARM,  // ARM
    ARM64 // ARM64
};

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

///////////////////////////////////////////////////////////////////////////////
// NT API declarations and structures for dynamic KnownDLLs and API Set resolution
///////////////////////////////////////////////////////////////////////////////

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// NT string structure
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef const UNICODE_STRING *PCUNICODE_STRING;

// Object attributes structure
typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

#define DIRECTORY_QUERY 0x0001
#define OBJ_CASE_INSENSITIVE 0x00000040L

// InitializeObjectAttributes macro
#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
    (p)->RootDirectory = r; \
    (p)->Attributes = a; \
    (p)->ObjectName = n; \
    (p)->SecurityDescriptor = s; \
    (p)->SecurityQualityOfService = NULL; \
}

// NT API function pointer types
typedef NTSTATUS (NTAPI* NtQueryInformationProcessFunc)(
    HANDLE ProcessHandle,
    DWORD ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS (NTAPI* NtOpenDirectoryObjectFunc)(
    PHANDLE DirectoryHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);

typedef NTSTATUS (NTAPI* NtQueryDirectoryObjectFunc)(
    HANDLE DirectoryHandle,
    PVOID Buffer,
    ULONG Length,
    BOOLEAN ReturnSingleEntry,
    BOOLEAN RestartScan,
    PULONG Context,
    PULONG ReturnLength
);

typedef NTSTATUS (NTAPI* NtCloseFunc)(
    HANDLE Handle
);

typedef VOID (NTAPI* RtlInitUnicodeStringFunc)(
    PUNICODE_STRING DestinationString,
    PCWSTR SourceString
);

// Simplified PEB structure
typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN SpareBool;
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PVOID Ldr;
    PVOID ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PVOID FastPebLock;
    PVOID AtlThunkSListPtr;
    PVOID IFEOKey;
    PVOID CrossProcessFlags;
    PVOID KernelCallbackTable;
    ULONG SystemReserved;
    ULONG AtlThunkSListPtr32;
    PVOID ApiSetMap;  // API Set Schema address
} PEB, *PPEB;

typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PPEB PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

#define ProcessBasicInformation 0

// API Set structure definitions (adapted from ApiSet.h)
// API Set v2 structures
typedef struct _API_SET_VALUE_ENTRY_REDIRECTION_V2 {
    ULONG  NameOffset;
    USHORT NameLength;
    ULONG  ValueOffset;
    USHORT ValueLength;
} API_SET_VALUE_ENTRY_REDIRECTION_V2, *PAPI_SET_VALUE_ENTRY_REDIRECTION_V2;

typedef struct _API_SET_VALUE_ENTRY_V2 {
    ULONG NumberOfRedirections;
    API_SET_VALUE_ENTRY_REDIRECTION_V2 Redirections[1];
} API_SET_VALUE_ENTRY_V2, *PAPI_SET_VALUE_ENTRY_V2;

typedef struct _API_SET_NAMESPACE_ENTRY_V2 {
    ULONG NameOffset;
    ULONG NameLength;
    ULONG DataOffset;
} API_SET_NAMESPACE_ENTRY_V2, *PAPI_SET_NAMESPACE_ENTRY_V2;

typedef struct _API_SET_NAMESPACE_V2 {
    ULONG Version;
    ULONG Count;
    API_SET_NAMESPACE_ENTRY_V2 Array[1];
} API_SET_NAMESPACE_V2, *PAPI_SET_NAMESPACE_V2;

// API Set v4 structures
typedef struct _API_SET_VALUE_ENTRY_REDIRECTION_V4 {
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;
    ULONG ValueOffset;
    ULONG ValueLength;
} API_SET_VALUE_ENTRY_REDIRECTION_V4, *PAPI_SET_VALUE_ENTRY_REDIRECTION_V4;

typedef struct _API_SET_VALUE_ENTRY_V4 {
    ULONG Flags;
    ULONG NumberOfRedirections;
    API_SET_VALUE_ENTRY_REDIRECTION_V4 Redirections[1];
} API_SET_VALUE_ENTRY_V4, *PAPI_SET_VALUE_ENTRY_V4;

typedef struct _API_SET_NAMESPACE_ENTRY_V4 {
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;
    ULONG AliasOffset;
    ULONG AliasLength;
    ULONG DataOffset;
} API_SET_NAMESPACE_ENTRY_V4, *PAPI_SET_NAMESPACE_ENTRY_V4;

typedef struct _API_SET_NAMESPACE_V4 {
    ULONG Version;
    ULONG Size;
    ULONG Flags;
    ULONG Count;
    API_SET_NAMESPACE_ENTRY_V4 Array[1];
} API_SET_NAMESPACE_V4, *PAPI_SET_NAMESPACE_V4;

// API Set v6 structures
typedef struct _API_SET_NAMESPACE_ENTRY_V6 {
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;
    ULONG HashedLength;
    ULONG ValueOffset;
    ULONG ValueCount;
} API_SET_NAMESPACE_ENTRY_V6, *PAPI_SET_NAMESPACE_ENTRY_V6;

typedef struct _API_SET_VALUE_ENTRY_V6 {
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;
    ULONG ValueOffset;
    ULONG ValueLength;
} API_SET_VALUE_ENTRY_V6, *PAPI_SET_VALUE_ENTRY_V6;

typedef struct _API_SET_NAMESPACE_V6 {
    ULONG Version;
    ULONG Size;
    ULONG Flags;
    ULONG Count;
    ULONG EntryOffset;
    ULONG HashOffset;
    ULONG HashFactor;
} API_SET_NAMESPACE_V6, *PAPI_SET_NAMESPACE_V6;

// Unified API Set namespace structure
typedef struct _API_SET_NAMESPACE {
    union {
        ULONG Version;
        API_SET_NAMESPACE_V2 ApiSetNameSpaceV2;
        API_SET_NAMESPACE_V4 ApiSetNameSpaceV4;
        API_SET_NAMESPACE_V6 ApiSetNameSpaceV6;
    };
} API_SET_NAMESPACE, *PAPI_SET_NAMESPACE;

// Object directory information structure
typedef struct _OBJECT_DIRECTORY_INFORMATION {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, *POBJECT_DIRECTORY_INFORMATION;

///////////////////////////////////////////////////////////////////////////////
// KnownDLLs and API Set resolution functions
///////////////////////////////////////////////////////////////////////////////

/**
 * @brief 从系统读取 KnownDLLs 列表
 * @param isWow64 是否读取 32 位 KnownDLLs
 * @return KnownDLLs 名称集合
 */
std::set<std::string> GetKnownDllsFromSystem(bool isWow64)
{
    static std::set<std::string> cachedKnownDlls[2] = { {}, {} };
    static bool cached[2] = { false, false };

    int cacheIndex = isWow64 ? 1 : 0;
    if (cached[cacheIndex]) {
        return cachedKnownDlls[cacheIndex];
    }

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        return {};
    }

    auto NtOpenDirectoryObject = reinterpret_cast<NtOpenDirectoryObjectFunc>(
        GetProcAddress(hNtdll, "NtOpenDirectoryObject"));
    auto NtQueryDirectoryObject = reinterpret_cast<NtQueryDirectoryObjectFunc>(
        GetProcAddress(hNtdll, "NtQueryDirectoryObject"));
    auto NtCloseFuncPtr = reinterpret_cast<NtCloseFunc>(
        GetProcAddress(hNtdll, "NtClose"));
    auto RtlInitUnicodeStringPtr = reinterpret_cast<RtlInitUnicodeStringFunc>(
        GetProcAddress(hNtdll, "RtlInitUnicodeString"));

    if (!NtOpenDirectoryObject || !NtQueryDirectoryObject || !NtCloseFuncPtr || !RtlInitUnicodeStringPtr) {
        return {};
    }

    // 打开 \KnownDlls 或 \KnownDlls32
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES oa;
    HANDLE knownDllDir = INVALID_HANDLE_VALUE;
    const wchar_t* knownDllObjectName = isWow64 ? L"\\KnownDlls32" : L"\\KnownDlls";

    RtlInitUnicodeStringPtr(&name, knownDllObjectName);
    InitializeObjectAttributes(&oa, &name, 0, NULL, NULL);

    NTSTATUS status = NtOpenDirectoryObject(&knownDllDir, DIRECTORY_QUERY, &oa);
    if (!NT_SUCCESS(status)) {
        return {};
    }

    // 枚举目录对象
    BYTE buffer[4096];
    ULONG context = 0;
    ULONG returnLength;

    while (NT_SUCCESS(NtQueryDirectoryObject(
        knownDllDir,
        buffer,
        sizeof(buffer),
        FALSE,
        FALSE,
        &context,
        &returnLength))) {

        POBJECT_DIRECTORY_INFORMATION info = (POBJECT_DIRECTORY_INFORMATION)buffer;
        if (info->Name.Buffer && info->TypeName.Buffer) {
            std::wstring typeName(info->TypeName.Buffer, info->TypeName.Length / sizeof(WCHAR));
            if (typeName == L"Section") {
                std::wstring dllName(info->Name.Buffer, info->Name.Length / sizeof(WCHAR));

                // 转换为 ANSI
                int size = WideCharToMultiByte(CP_UTF8, 0, dllName.c_str(), -1, nullptr, 0, nullptr, nullptr);
                std::string ansiName(size - 1, 0);
                WideCharToMultiByte(CP_UTF8, 0, dllName.c_str(), -1, &ansiName[0], size, nullptr, nullptr);

                cachedKnownDlls[cacheIndex].insert(ansiName);
            }
        }
    }

    NtCloseFuncPtr(knownDllDir);
    cached[cacheIndex] = true;
    return cachedKnownDlls[cacheIndex];
}

/**
 * @brief 从 PEB 获取 API Set Namespace
 */
PAPI_SET_NAMESPACE GetApiSetNamespace()
{
    static PAPI_SET_NAMESPACE cachedNamespace = nullptr;
    static bool cached = false;

    if (cached) {
        return cachedNamespace;
    }

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        return nullptr;
    }

    auto NtQueryInformationProcess = reinterpret_cast<NtQueryInformationProcessFunc>(
        GetProcAddress(hNtdll, "NtQueryInformationProcess"));

    if (!NtQueryInformationProcess) {
        return nullptr;
    }

    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength;
    NTSTATUS status = NtQueryInformationProcess(
        GetCurrentProcess(),
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        &returnLength
    );

    if (!NT_SUCCESS(status) || !pbi.PebBaseAddress) {
        return nullptr;
    }

    cachedNamespace = static_cast<PAPI_SET_NAMESPACE>(pbi.PebBaseAddress->ApiSetMap);
    cached = true;
    return cachedNamespace;
}

/**
 * @brief 将 API Set 名称解析为物理 DLL 名称
 * @param apiSetName API Set 虚拟名称（如 "api-ms-win-crt-runtime-l1-1-0"）
 * @return 物理 DLL 名称（如 "ucrtbase.dll"），失败返回空字符串
 */
std::string ResolveApiSetToDll(const std::string& apiSetName)
{
    std::string lowerName = apiSetName;
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

    // 移除前缀
    std::string searchName;
    if (lowerName.find("api-ms-win-") == 0) {
        searchName = lowerName.substr(11);
    } else if (lowerName.find("ext-ms-") == 0) {
        searchName = lowerName.substr(7);
    } else {
        return "";
    }

    PAPI_SET_NAMESPACE apiSetMap = GetApiSetNamespace();
    if (!apiSetMap) {
        return "";
    }

    ULONG_PTR base = reinterpret_cast<ULONG_PTR>(apiSetMap);

    // 根据版本解析
    switch (apiSetMap->Version) {
        case 2: {
            PAPI_SET_NAMESPACE_V2 mapV2 = &apiSetMap->ApiSetNameSpaceV2;
            for (ULONG i = 0; i < mapV2->Count; i++) {
                PAPI_SET_NAMESPACE_ENTRY_V2 entry = &mapV2->Array[i];
                PWCHAR nameBuffer = reinterpret_cast<PWCHAR>(base + entry->NameOffset);
                std::wstring entryName(nameBuffer, entry->NameLength / sizeof(WCHAR));

                std::string entryNameLower;
                std::transform(entryName.begin(), entryName.end(),
                             std::back_inserter(entryNameLower), ::tolower);

                if (entryNameLower.find(searchName) == 0) {
                    PAPI_SET_VALUE_ENTRY_V2 valueEntry = reinterpret_cast<PAPI_SET_VALUE_ENTRY_V2>(
                        base + entry->DataOffset);
                    if (valueEntry->NumberOfRedirections > 0) {
                        PWCHAR valueBuffer = reinterpret_cast<PWCHAR>(
                            base + valueEntry->Redirections[0].ValueOffset);
                        std::wstring dllName(valueBuffer, valueEntry->Redirections[0].ValueLength / sizeof(WCHAR));

                        int size = WideCharToMultiByte(CP_UTF8, 0, dllName.c_str(), -1, nullptr, 0, nullptr, nullptr);
                        std::string result(size - 1, 0);
                        WideCharToMultiByte(CP_UTF8, 0, dllName.c_str(), -1, &result[0], size, nullptr, nullptr);
                        return result;
                    }
                }
            }
            break;
        }
        case 4: {
            PAPI_SET_NAMESPACE_V4 mapV4 = &apiSetMap->ApiSetNameSpaceV4;
            for (ULONG i = 0; i < mapV4->Count; i++) {
                PAPI_SET_NAMESPACE_ENTRY_V4 entry = &mapV4->Array[i];
                PWCHAR nameBuffer = reinterpret_cast<PWCHAR>(base + entry->NameOffset);
                std::wstring entryName(nameBuffer, entry->NameLength / sizeof(WCHAR));

                std::string entryNameLower;
                std::transform(entryName.begin(), entryName.end(),
                             std::back_inserter(entryNameLower), ::tolower);

                if (entryNameLower.find(searchName) == 0) {
                    PAPI_SET_VALUE_ENTRY_V4 valueEntry = reinterpret_cast<PAPI_SET_VALUE_ENTRY_V4>(
                        base + entry->DataOffset);
                    if (valueEntry->NumberOfRedirections > 0) {
                        PWCHAR valueBuffer = reinterpret_cast<PWCHAR>(
                            base + valueEntry->Redirections[0].ValueOffset);
                        std::wstring dllName(valueBuffer, valueEntry->Redirections[0].ValueLength / sizeof(WCHAR));

                        int size = WideCharToMultiByte(CP_UTF8, 0, dllName.c_str(), -1, nullptr, 0, nullptr, nullptr);
                        std::string result(size - 1, 0);
                        WideCharToMultiByte(CP_UTF8, 0, dllName.c_str(), -1, &result[0], size, nullptr, nullptr);
                        return result;
                    }
                }
            }
            break;
        }
        case 6: {
            PAPI_SET_NAMESPACE_V6 mapV6 = &apiSetMap->ApiSetNameSpaceV6;
            PAPI_SET_NAMESPACE_ENTRY_V6 entries = reinterpret_cast<PAPI_SET_NAMESPACE_ENTRY_V6>(
                base + mapV6->EntryOffset);

            for (ULONG i = 0; i < mapV6->Count; i++) {
                PAPI_SET_NAMESPACE_ENTRY_V6 entry = &entries[i];
                PWCHAR nameBuffer = reinterpret_cast<PWCHAR>(base + entry->NameOffset);
                std::wstring entryName(nameBuffer, entry->NameLength / sizeof(WCHAR));

                std::string entryNameLower;
                std::transform(entryName.begin(), entryName.end(),
                             std::back_inserter(entryNameLower), ::tolower);

                if (entryNameLower.find(searchName) == 0) {
                    PAPI_SET_VALUE_ENTRY_V6 valueEntry = reinterpret_cast<PAPI_SET_VALUE_ENTRY_V6>(
                        base + entry->ValueOffset);
                    if (entry->ValueCount > 0) {
                        PWCHAR valueBuffer = reinterpret_cast<PWCHAR>(
                            base + valueEntry->ValueOffset);
                        std::wstring dllName(valueBuffer, valueEntry->ValueLength / sizeof(WCHAR));

                        int size = WideCharToMultiByte(CP_UTF8, 0, dllName.c_str(), -1, nullptr, 0, nullptr, nullptr);
                        std::string result(size - 1, 0);
                        WideCharToMultiByte(CP_UTF8, 0, dllName.c_str(), -1, &result[0], size, nullptr, nullptr);
                        return result;
                    }
                }
            }
            break;
        }
        default:
            break;
    }

    return "";
}

// 前向声明
std::vector<std::string> ParseFileDependencies(const char *filePath);
bool IsCppRuntimeDLL(const std::string &dllName);
bool IsSystemCoreDLL(const std::string &dllName);
bool IsSystemDirectory(const std::string &dllPath);
std::vector<std::string> GetDependentDLLs(const char *executablePath, bool recursive = false, const std::vector<std::string> &extraDirs = {}, PEArchitecture targetArch = PEArchitecture::Unknown);
std::string FindDLLFile(const std::string &dllName, const std::string &exeDir, const std::vector<std::string> &extraDirs = {}, PEArchitecture targetArch = PEArchitecture::Unknown);
void GetRecursiveDependentDLLs(const std::string &dllPath, const std::string &exeDir, int depth, const std::vector<std::string> &extraDirs = {}, PEArchitecture targetArch = PEArchitecture::Unknown);
bool CopyDependentDLLs(const std::vector<std::string> &dllList, const std::string &exePath, const std::string &destDir, const std::vector<std::string> &extraDirs = {}, bool copyAll = false, PEArchitecture targetArch = PEArchitecture::Unknown);

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

// 全局变量：要忽略的 DLL 名称列表
std::set<std::string> g_ignoredDLLNames;
// 全局变量：要忽略的 DLL 文件路径列表
std::set<std::string> g_ignoredDLLPaths;
// 全局变量：要忽略的文件夹路径列表
std::set<std::string> g_ignoredDirectories;

// 递归获取DLL依赖
void GetRecursiveDependentDLLs(const std::string &dllPath, const std::string &exeDir, int depth, const std::vector<std::string> &extraDirs, PEArchitecture targetArch)
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
std::vector<std::string> GetDependentDLLs(const char *executablePath, bool recursive, const std::vector<std::string> &extraDirs, PEArchitecture targetArch)
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

// 获取系统目录路径
std::string GetSystemDirectory()
{
    char systemDir[MAX_PATH];
    GetSystemDirectoryA(systemDir, MAX_PATH);
    return std::string(systemDir);
}

// 获取Windows目录路径
std::string GetWindowsDirectory()
{
    char windowsDir[MAX_PATH];
    GetWindowsDirectoryA(windowsDir, MAX_PATH);
    return std::string(windowsDir);
}

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
    std::string systemDir = GetSystemDirectory();
    std::string windowsDir = GetWindowsDirectory();

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

// 获取环境变量PATH中的目录列表
std::vector<std::string> GetPathDirectories()
{
    std::vector<std::string> pathDirs;
    char *pathEnv;
    size_t len;
    _dupenv_s(&pathEnv, &len, "PATH");

    if (pathEnv)
    {
        char *context = nullptr;
        char *token = strtok_s(pathEnv, ";", &context);
        while (token != nullptr)
        {
            pathDirs.push_back(std::string(token));
            token = strtok_s(nullptr, ";", &context);
        }
        free(pathEnv);
    }

    return pathDirs;
}

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

// 搜索DLL文件（支持架构感知查找）
std::string FindDLLFile(const std::string &dllName, const std::string &exeDir, const std::vector<std::string> &extraDirs, PEArchitecture targetArch)
{
    std::string foundPath = ""; // 用于存储找到的路径（如果没有架构匹配）

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
    dllPath = (std::filesystem::path(GetSystemDirectory()) / dllName).string();
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
    dllPath = (std::filesystem::path(GetWindowsDirectory()) / dllName).string();
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
bool CopyDependentDLLs(const std::vector<std::string> &dllList, const std::string &exePath, const std::string &destDir, const std::vector<std::string> &extraDirs, bool copyAll, PEArchitecture targetArch)
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

    if (!g_ignoredDLLNames.empty() || !g_ignoredDLLPaths.empty() || !g_ignoredDirectories.empty())
    {
        std::cout << "Note: ";
        ConsoleColors::PrintLn(ConsoleColors::MAGENTA, std::to_string(g_ignoredDLLNames.size() + g_ignoredDLLPaths.size() + g_ignoredDirectories.size()) + " item(s) in ignore list");
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
                std::string testPath = (std::filesystem::path(GetSystemDirectory()) / dllName).string();
                if (PathFileExistsA(testPath.c_str()))
                {
                    anyFileFound = true;
                }
            }

            if (!anyFileFound)
            {
                std::string testPath = (std::filesystem::path(GetWindowsDirectory()) / dllName).string();
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

int main(int argc, char *argv[])
{
    if (argc < 2 || argc > 10)
    {
        std::cout << "Usage: " << argv[0] << " <executable_path> [options]" << std::endl;
        std::cout << "Options:" << std::endl;
        std::cout << "  --release [depth]     Release mode: recursively analyze dependencies (default depth: 2)" << std::endl;
        std::cout << "                         and copy DLLs to the executable's directory" << std::endl;
        std::cout << "  --recursive [depth]   Recursively analyze all DLL dependencies (default depth: 20)" << std::endl;
        std::cout << "  --copy <target_dir>   Copy dependent DLLs to specified directory" << std::endl;
        std::cout << "  --copy-exe-dir        Copy dependent DLLs to the executable's directory" << std::endl;
        std::cout << "  --copy-all            Copy all DLLs including system core DLLs" << std::endl;
        std::cout << "  --search-dirs <file>  Load additional search directories from file (one directory per line)" << std::endl;
        std::cout << "  --ignore-dll <file>   Load ignore list from file (DLL names, paths, or directories)" << std::endl;
        std::cout << "\nExamples:" << std::endl;
        std::cout << "  " << argv[0] << " C:\\Path\\To\\YourApp.exe" << std::endl;
        std::cout << "  " << argv[0] << " C:\\Path\\To\\YourApp.exe --release" << std::endl;
        std::cout << "  " << argv[0] << " C:\\Path\\To\\YourApp.exe --release 3" << std::endl;
        std::cout << "  " << argv[0] << " C:\\Path\\To\\YourApp.exe --recursive" << std::endl;
        std::cout << "  " << argv[0] << " C:\\Path\\To\\YourApp.exe --recursive 10" << std::endl;
        std::cout << "  " << argv[0] << " C:\\Path\\To\\YourApp.exe --recursive --copy C:\\DestDir" << std::endl;
        std::cout << "  " << argv[0] << " C:\\Path\\To\\YourApp.exe --copy-exe-dir" << std::endl;
        std::cout << "  " << argv[0] << " C:\\Path\\To\\YourApp.exe --copy-exe-dir --copy-all" << std::endl;
        std::cout << "  " << argv[0] << " C:\\Path\\To\\YourApp.exe --search-dirs test_path.txt" << std::endl;
        std::cout << "  " << argv[0] << " C:\\Path\\To\\YourApp.exe --release --ignore-dll ignore.txt" << std::endl;
        std::cout << "  " << argv[0] << " C:\\Path\\To\\YourApp.exe --release --search-dirs test_path.txt --ignore-dll ignore.txt" << std::endl;
        std::cout << "\nNote: When using --recursive with --copy, all dependencies at all levels will be copied." << std::endl;
        std::cout << "      By default, system core DLLs will be skipped during copy." << std::endl;
        std::cout << "      Use --copy-all to include system core DLLs." << std::endl;
        std::cout << "      The --search-dirs file should contain one directory path per line." << std::endl;
        std::cout << "      Lines starting with # or ; are treated as comments and ignored." << std::endl;
        std::cout << "      The --ignore-dll file can contain DLL names, DLL paths, or directory paths." << std::endl;
        std::cout << "      --release mode is equivalent to --recursive 2 --copy-exe-dir" << std::endl;
        return 1;
    }

    auto exe_path = argv[1];
    bool copyMode = false;
    bool recursiveMode = false;
    bool releaseMode = false;
    bool copyAllMode = false;
    std::string destDir;
    std::string searchDirsFile;
    std::string ignoreDllFile;
    std::vector<std::string> extraSearchDirs;

    // 解析命令行参数
    int argIndex = 2;
    while (argIndex < argc)
    {
        if (strcmp(argv[argIndex], "--release") == 0)
        {
            releaseMode = true;
            recursiveMode = true;
            copyMode = true;
            // 获取可执行文件所在目录作为目标目录
            destDir = std::filesystem::path(exe_path).parent_path().string();
            argIndex++;

            // 检查是否指定了递归深度
            if (argIndex < argc && argv[argIndex][0] != '-')
            {
                // 尝试解析为数字
                try
                {
                    int depth = std::stoi(argv[argIndex]);
                    if (depth <= 0)
                    {
                        std::cerr << "Error: Recursion depth must be a positive number, got: " << depth << std::endl;
                        return 1;
                    }
                    g_maxRecursionDepth = depth;
                    std::cout << "Info: Release mode: Maximum recursion depth set to: " << g_maxRecursionDepth << std::endl;
                    argIndex++;
                }
                catch (const std::exception &e)
                {
                    std::cerr << "Error: Invalid recursion depth value: " << argv[argIndex] << std::endl;
                    return 1;
                }
            }
            else
            {
                // 使用默认值 2
                g_maxRecursionDepth = 2;
                std::cout << "Info: Release mode: Maximum recursion depth set to: " << g_maxRecursionDepth << " (default)" << std::endl;
            }
        }
        else if (strcmp(argv[argIndex], "--recursive") == 0)
        {
            recursiveMode = true;
            argIndex++;

            // 检查是否指定了递归深度
            if (argIndex < argc && argv[argIndex][0] != '-')
            {
                // 尝试解析为数字
                try
                {
                    int depth = std::stoi(argv[argIndex]);
                    if (depth <= 0)
                    {
                        std::cerr << "Error: Recursion depth must be a positive number, got: " << depth << std::endl;
                        return 1;
                    }
                    g_maxRecursionDepth = depth;
                    std::cout << "Info: Maximum recursion depth set to: " << g_maxRecursionDepth << std::endl;
                    argIndex++;
                }
                catch (const std::exception &e)
                {
                    std::cerr << "Error: Invalid recursion depth value: " << argv[argIndex] << std::endl;
                    return 1;
                }
            }
            else
            {
                // 使用默认值 20
                g_maxRecursionDepth = 20;
            }
        }
        else if (strcmp(argv[argIndex], "--copy") == 0 && argIndex + 1 < argc)
        {
            copyMode = true;
            destDir = argv[argIndex + 1];
            argIndex += 2;
        }
        else if (strcmp(argv[argIndex], "--copy-exe-dir") == 0)
        {
            copyMode = true;
            // 获取可执行文件所在目录
            destDir = std::filesystem::path(exe_path).parent_path().string();
            argIndex++;
        }
        else if (strcmp(argv[argIndex], "--copy-all") == 0)
        {
            copyAllMode = true;
            argIndex++;
        }
        else if (strcmp(argv[argIndex], "--search-dirs") == 0 && argIndex + 1 < argc)
        {
            searchDirsFile = argv[argIndex + 1];
            extraSearchDirs = LoadExtraSearchDirectories(searchDirsFile);
            if (extraSearchDirs.empty())
            {
                std::cout << "Warning: No extra search directories loaded from: " << searchDirsFile << std::endl;
            }
            argIndex += 2;
        }
        else if (strcmp(argv[argIndex], "--ignore-dll") == 0 && argIndex + 1 < argc)
        {
            ignoreDllFile = argv[argIndex + 1];
            LoadIgnoredDLLs(ignoreDllFile);
            argIndex += 2;
        }
        else
        {
            std::cerr << "Error: Invalid command line argument: " << argv[argIndex] << std::endl;
            return 1;
        }
    }

    // 检测目标文件的架构
    ConsoleColors::PrintLn(ConsoleColors::CYAN, "=== Analyzing Target Executable ===");
    PEArchitecture targetArch = DetectPEArchitecture(exe_path);
    if (targetArch == PEArchitecture::Unknown)
    {
        std::cerr << "Error: Unable to detect PE architecture of target file" << std::endl;
        return 1;
    }
    std::cout << "Target file architecture: ";
    ConsoleColors::PrintLn(ConsoleColors::BRIGHT_GREEN, ArchitectureToString(targetArch));

    auto dlls = GetDependentDLLs(exe_path, recursiveMode, extraSearchDirs, targetArch);

    std::cout << "\n";
    ConsoleColors::PrintLn(ConsoleColors::CYAN, "=== Dependent DLL List ===");
    for (const auto &dll : dlls)
    {
        std::cout << dll << std::endl;
    }
    std::cout << "Total: ";
    ConsoleColors::PrintLn(ConsoleColors::BRIGHT_CYAN, std::to_string(dlls.size()) + " DLL(s)");

    // 如果启用了复制模式，则复制DLL文件
    if (copyMode)
    {
        std::cout << "\n";
        ConsoleColors::PrintLn(ConsoleColors::CYAN, "=== Starting to Copy DLL Files ===");
        if (CopyDependentDLLs(dlls, exe_path, destDir, extraSearchDirs, copyAllMode, targetArch))
        {
            ConsoleColors::PrintLn(ConsoleColors::GREEN, "✓ All DLL files copied successfully!");
        }
        else
        {
            ConsoleColors::PrintLn(ConsoleColors::RED, "✗ Some DLL files failed to copy, please check error messages");
            return 1;
        }
    }

    return 0;
}