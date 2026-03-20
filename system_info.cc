#include "system_info.h"
#include <windows.h>
#include <iostream>
#include <algorithm>
#include <cstring>

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

// 获取系统目录路径
std::string GetSystemDirPath()
{
    char systemDir[MAX_PATH];
    GetSystemDirectoryA(systemDir, MAX_PATH);
    return std::string(systemDir);
}

// 获取Windows目录路径
std::string GetWindowsDirPath()
{
    char windowsDir[MAX_PATH];
    GetWindowsDirectoryA(windowsDir, MAX_PATH);
    return std::string(windowsDir);
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

// 从系统读取 KnownDLLs 列表
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

// 从 PEB 获取 API Set Namespace
void* GetApiSetNamespace()
{
    static void* cachedNamespace = nullptr;
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

    cachedNamespace = static_cast<void*>(pbi.PebBaseAddress->ApiSetMap);
    cached = true;
    return cachedNamespace;
}

// 将 API Set 名称解析为物理 DLL 名称
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

    PAPI_SET_NAMESPACE apiSetMap = static_cast<PAPI_SET_NAMESPACE>(GetApiSetNamespace());
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
