#pragma once

#include <windows.h>

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
