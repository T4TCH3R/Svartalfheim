#pragma once

#include <windows.h>
#include <winhttp.h>

#include "ntdll.h"

#include "Macros.h"

typedef struct _SYS_INFO {
    void*   pAddress;
    WORD    syscall;
} SYS_INFO, *PSYS_INFO;


typedef struct _INSTANCE
{
    struct
    {
        void* pStartAddr;
        void* pEnd;
        DWORD dwSize;
    } Info;

    struct
    {
        void *Kernel32;
        void *Kernelbase;
        void *Ntdll;
        void *Winhttp;
    } Module;

    struct
    {
        D_API(LocalAlloc);
        D_API(LocalReAlloc);
        D_API(LocalFree);
        D_API(RtlCaptureContext);

        void* RtlUserThreadStart;
        void* RtlExitUserThread;
        void* VirtualFree;
        void* LoadLibraryA;

    } Win32;

    struct
    {
        void* WinHttpOpen;
        void* WinHttpConnect;
        void* WinHttpOpenRequest;
        void* WinHttpSendRequest;
        void* WinHttpReceiveResponse;
        void* WinHttpReadData;
        void* WinHttpCloseHandle;
    } Transport;

    struct
    {
        SYS_INFO NtAllocateVirtualMemory;
        SYS_INFO NtProtectVirtualMemory;
        SYS_INFO NtCreateThreadEx;
        SYS_INFO NtGetContextThread;
        SYS_INFO NtSetContextThread;
        SYS_INFO NtResumeThread;
        SYS_INFO NtContinue;

    } Sys;

} INSTANCE, *PINSTANCE;