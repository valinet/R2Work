// Example of a library that, when injected into a process, helps Windhawk
// inject processes created by inaccessible processes early on
// ==========================================================================
// Valentin-Gabriel Radu, valentin.radu@valinet.ro
//
// Upstream issue:
//    https://github.com/ramensoftware/windhawk/issues/197
//
// Instead of <windows.h>, using <phnt.h> which gives access to
// native Nt* APIs, get a copy from:
//    https://github.com/mrexodia/phnt-single-header/releases/latest/download/phnt.h
//
// Compilation tested to work only in Release mode
//
#define _CRT_SECURE_NO_WARNINGS
#define PHNT_VERSION PHNT_WIN11
#include "phnt.h"
//
// Do not link in the CRT; instead, only link ntdll.lib
// This is required if the library is set up to be injected as a verifier engine
// DLL, since such DLLs are injected very early on in process lifetime,
// even before kernel32.dll; we aim to maintain the "natural" order of
// loading DLLs for that process, so we restrict this to only using ntdll APIs,
// which always is the first and mandatory loaded DLL in a process.
//
#pragma comment(linker,"/DEFAULTLIB:ntdll.lib")
//
// Specify out custom entry point
//
#pragma comment(linker,"/ENTRY:DllMain")
//
// Exports for when this library is loaded via DLL load hijacking; this is
// just an example where this library impersonates mpr.dll; replace depending
// on your use case.
//
// Generate export declarations using, for example:
//    https://github.com/iMoD1998/DLL-Proxy-Generator
//
#pragma comment(linker,"/export:DoBroadcastSystemMessage=C:\\Windows\\System32\\mpr.DoBroadcastSystemMessage")
#pragma comment(linker,"/export:DoCommandLinePrompt=C:\\Windows\\System32\\mpr.DoCommandLinePrompt")
#pragma comment(linker,"/export:DoPasswordDialog=C:\\Windows\\System32\\mpr.DoPasswordDialog")
#pragma comment(linker,"/export:DoProfileErrorDialog=C:\\Windows\\System32\\mpr.DoProfileErrorDialog")
#pragma comment(linker,"/export:ShowReconnectDialog=C:\\Windows\\System32\\mpr.ShowReconnectDialog")
#pragma comment(linker,"/export:ShowReconnectDialogEnd=C:\\Windows\\System32\\mpr.ShowReconnectDialogEnd")
#pragma comment(linker,"/export:ShowReconnectDialogUI=C:\\Windows\\System32\\mpr.ShowReconnectDialogUI")
#pragma comment(linker,"/export:WNetConnectionDialog2=C:\\Windows\\System32\\mpr.WNetConnectionDialog2")
#pragma comment(linker,"/export:WNetDisconnectDialog2=C:\\Windows\\System32\\mpr.WNetDisconnectDialog2")
#pragma comment(linker,"/export:I_MprSaveConn=C:\\Windows\\System32\\mpr.I_MprSaveConn")
#pragma comment(linker,"/export:MultinetGetConnectionPerformanceA=C:\\Windows\\System32\\mpr.MultinetGetConnectionPerformanceA")
#pragma comment(linker,"/export:MultinetGetConnectionPerformanceW=C:\\Windows\\System32\\mpr.MultinetGetConnectionPerformanceW")
#pragma comment(linker,"/export:MultinetGetErrorTextA=C:\\Windows\\System32\\mpr.MultinetGetErrorTextA")
#pragma comment(linker,"/export:MultinetGetErrorTextW=C:\\Windows\\System32\\mpr.MultinetGetErrorTextW")
#pragma comment(linker,"/export:WNetAddConnection2A=C:\\Windows\\System32\\mpr.WNetAddConnection2A")
#pragma comment(linker,"/export:WNetAddConnection2W=C:\\Windows\\System32\\mpr.WNetAddConnection2W")
#pragma comment(linker,"/export:WNetAddConnection3A=C:\\Windows\\System32\\mpr.WNetAddConnection3A")
#pragma comment(linker,"/export:WNetAddConnection3W=C:\\Windows\\System32\\mpr.WNetAddConnection3W")
#pragma comment(linker,"/export:WNetAddConnection4A=C:\\Windows\\System32\\mpr.WNetAddConnection4A")
#pragma comment(linker,"/export:WNetAddConnection4W=C:\\Windows\\System32\\mpr.WNetAddConnection4W")
#pragma comment(linker,"/export:WNetAddConnectionA=C:\\Windows\\System32\\mpr.WNetAddConnectionA")
#pragma comment(linker,"/export:WNetAddConnectionW=C:\\Windows\\System32\\mpr.WNetAddConnectionW")
#pragma comment(linker,"/export:WNetCancelConnection2A=C:\\Windows\\System32\\mpr.WNetCancelConnection2A")
#pragma comment(linker,"/export:WNetCancelConnection2W=C:\\Windows\\System32\\mpr.WNetCancelConnection2W")
#pragma comment(linker,"/export:WNetCancelConnectionA=C:\\Windows\\System32\\mpr.WNetCancelConnectionA")
#pragma comment(linker,"/export:WNetCancelConnectionW=C:\\Windows\\System32\\mpr.WNetCancelConnectionW")
#pragma comment(linker,"/export:WNetClearConnections=C:\\Windows\\System32\\mpr.WNetClearConnections")
#pragma comment(linker,"/export:WNetCloseEnum=C:\\Windows\\System32\\mpr.WNetCloseEnum")
#pragma comment(linker,"/export:WNetConnectionDialog=C:\\Windows\\System32\\mpr.WNetConnectionDialog")
#pragma comment(linker,"/export:WNetConnectionDialog1A=C:\\Windows\\System32\\mpr.WNetConnectionDialog1A")
#pragma comment(linker,"/export:WNetConnectionDialog1W=C:\\Windows\\System32\\mpr.WNetConnectionDialog1W")
#pragma comment(linker,"/export:WNetDirectoryNotifyA=C:\\Windows\\System32\\mpr.WNetDirectoryNotifyA")
#pragma comment(linker,"/export:WNetDirectoryNotifyW=C:\\Windows\\System32\\mpr.WNetDirectoryNotifyW")
#pragma comment(linker,"/export:WNetDisconnectDialog=C:\\Windows\\System32\\mpr.WNetDisconnectDialog")
#pragma comment(linker,"/export:WNetDisconnectDialog1A=C:\\Windows\\System32\\mpr.WNetDisconnectDialog1A")
#pragma comment(linker,"/export:WNetDisconnectDialog1W=C:\\Windows\\System32\\mpr.WNetDisconnectDialog1W")
#pragma comment(linker,"/export:WNetEnumResourceA=C:\\Windows\\System32\\mpr.WNetEnumResourceA")
#pragma comment(linker,"/export:WNetEnumResourceW=C:\\Windows\\System32\\mpr.WNetEnumResourceW")
#pragma comment(linker,"/export:WNetFormatNetworkNameA=C:\\Windows\\System32\\mpr.WNetFormatNetworkNameA")
#pragma comment(linker,"/export:WNetFormatNetworkNameW=C:\\Windows\\System32\\mpr.WNetFormatNetworkNameW")
#pragma comment(linker,"/export:WNetGetConnection2A=C:\\Windows\\System32\\mpr.WNetGetConnection2A")
#pragma comment(linker,"/export:WNetGetConnection2W=C:\\Windows\\System32\\mpr.WNetGetConnection2W")
#pragma comment(linker,"/export:WNetGetConnection3A=C:\\Windows\\System32\\mpr.WNetGetConnection3A")
#pragma comment(linker,"/export:WNetGetConnection3W=C:\\Windows\\System32\\mpr.WNetGetConnection3W")
#pragma comment(linker,"/export:WNetGetConnectionA=C:\\Windows\\System32\\mpr.WNetGetConnectionA")
#pragma comment(linker,"/export:WNetGetConnectionW=C:\\Windows\\System32\\mpr.WNetGetConnectionW")
#pragma comment(linker,"/export:WNetGetDirectoryTypeA=C:\\Windows\\System32\\mpr.WNetGetDirectoryTypeA")
#pragma comment(linker,"/export:WNetGetDirectoryTypeW=C:\\Windows\\System32\\mpr.WNetGetDirectoryTypeW")
#pragma comment(linker,"/export:WNetGetHomeDirectoryW=C:\\Windows\\System32\\mpr.WNetGetHomeDirectoryW")
#pragma comment(linker,"/export:WNetGetLastErrorA=C:\\Windows\\System32\\mpr.WNetGetLastErrorA")
#pragma comment(linker,"/export:WNetGetLastErrorW=C:\\Windows\\System32\\mpr.WNetGetLastErrorW")
#pragma comment(linker,"/export:WNetGetNetworkInformationA=C:\\Windows\\System32\\mpr.WNetGetNetworkInformationA")
#pragma comment(linker,"/export:WNetGetNetworkInformationW=C:\\Windows\\System32\\mpr.WNetGetNetworkInformationW")
#pragma comment(linker,"/export:WNetGetPropertyTextA=C:\\Windows\\System32\\mpr.WNetGetPropertyTextA")
#pragma comment(linker,"/export:WNetGetPropertyTextW=C:\\Windows\\System32\\mpr.WNetGetPropertyTextW")
#pragma comment(linker,"/export:WNetGetProviderNameA=C:\\Windows\\System32\\mpr.WNetGetProviderNameA")
#pragma comment(linker,"/export:WNetGetProviderNameW=C:\\Windows\\System32\\mpr.WNetGetProviderNameW")
#pragma comment(linker,"/export:WNetGetProviderTypeA=C:\\Windows\\System32\\mpr.WNetGetProviderTypeA")
#pragma comment(linker,"/export:WNetGetProviderTypeW=C:\\Windows\\System32\\mpr.WNetGetProviderTypeW")
#pragma comment(linker,"/export:WNetGetResourceInformationA=C:\\Windows\\System32\\mpr.WNetGetResourceInformationA")
#pragma comment(linker,"/export:WNetGetResourceInformationW=C:\\Windows\\System32\\mpr.WNetGetResourceInformationW")
#pragma comment(linker,"/export:WNetGetResourceParentA=C:\\Windows\\System32\\mpr.WNetGetResourceParentA")
#pragma comment(linker,"/export:WNetGetResourceParentW=C:\\Windows\\System32\\mpr.WNetGetResourceParentW")
#pragma comment(linker,"/export:WNetGetSearchDialog=C:\\Windows\\System32\\mpr.WNetGetSearchDialog")
#pragma comment(linker,"/export:WNetGetUniversalNameA=C:\\Windows\\System32\\mpr.WNetGetUniversalNameA")
#pragma comment(linker,"/export:WNetGetUniversalNameW=C:\\Windows\\System32\\mpr.WNetGetUniversalNameW")
#pragma comment(linker,"/export:WNetGetUserA=C:\\Windows\\System32\\mpr.WNetGetUserA")
#pragma comment(linker,"/export:WNetGetUserW=C:\\Windows\\System32\\mpr.WNetGetUserW")
#pragma comment(linker,"/export:WNetLogonNotify=C:\\Windows\\System32\\mpr.WNetLogonNotify")
#pragma comment(linker,"/export:WNetOpenEnumA=C:\\Windows\\System32\\mpr.WNetOpenEnumA")
#pragma comment(linker,"/export:WNetOpenEnumW=C:\\Windows\\System32\\mpr.WNetOpenEnumW")
#pragma comment(linker,"/export:WNetPasswordChangeNotify=C:\\Windows\\System32\\mpr.WNetPasswordChangeNotify")
#pragma comment(linker,"/export:WNetPropertyDialogA=C:\\Windows\\System32\\mpr.WNetPropertyDialogA")
#pragma comment(linker,"/export:WNetPropertyDialogW=C:\\Windows\\System32\\mpr.WNetPropertyDialogW")
#pragma comment(linker,"/export:WNetRestoreAllConnectionsW=C:\\Windows\\System32\\mpr.WNetRestoreAllConnectionsW")
#pragma comment(linker,"/export:WNetRestoreSingleConnectionW=C:\\Windows\\System32\\mpr.WNetRestoreSingleConnectionW")
#pragma comment(linker,"/export:WNetSetConnectionA=C:\\Windows\\System32\\mpr.WNetSetConnectionA")
#pragma comment(linker,"/export:WNetSetConnectionW=C:\\Windows\\System32\\mpr.WNetSetConnectionW")
#pragma comment(linker,"/export:WNetSetLastErrorA=C:\\Windows\\System32\\mpr.WNetSetLastErrorA")
#pragma comment(linker,"/export:WNetSetLastErrorW=C:\\Windows\\System32\\mpr.WNetSetLastErrorW")
#pragma comment(linker,"/export:WNetSupportGlobalEnum=C:\\Windows\\System32\\mpr.WNetSupportGlobalEnum")
#pragma comment(linker,"/export:WNetUseConnection4A=C:\\Windows\\System32\\mpr.WNetUseConnection4A")
#pragma comment(linker,"/export:WNetUseConnection4W=C:\\Windows\\System32\\mpr.WNetUseConnection4W")
#pragma comment(linker,"/export:WNetUseConnectionA=C:\\Windows\\System32\\mpr.WNetUseConnectionA")
#pragma comment(linker,"/export:WNetUseConnectionW=C:\\Windows\\System32\\mpr.WNetUseConnectionW")
//

//
// Define constants and structs used when library is set up as verifier engine.
//
#define DLL_PROCESS_VERIFIER 4

typedef struct _RTL_VERIFIER_THUNK_DESCRIPTOR {
    PCHAR ThunkName;
    PVOID ThunkOldAddress;
    PVOID ThunkNewAddress;
} RTL_VERIFIER_THUNK_DESCRIPTOR, * PRTL_VERIFIER_THUNK_DESCRIPTOR;

typedef struct _RTL_VERIFIER_DLL_DESCRIPTOR {
    PWCHAR DllName;
    ULONG DllFlags;
    PVOID DllAddress;
    PRTL_VERIFIER_THUNK_DESCRIPTOR DllThunks;
} RTL_VERIFIER_DLL_DESCRIPTOR, * PRTL_VERIFIER_DLL_DESCRIPTOR;

typedef void (NTAPI* RTL_VERIFIER_DLL_LOAD_CALLBACK) (
    PWSTR DllName,
    PVOID DllBase,
    SIZE_T DllSize,
    PVOID Reserved);
typedef void (NTAPI* RTL_VERIFIER_DLL_UNLOAD_CALLBACK) (
    PWSTR DllName,
    PVOID DllBase,
    SIZE_T DllSize,
    PVOID Reserved);
typedef void (NTAPI* RTL_VERIFIER_NTDLLHEAPFREE_CALLBACK) (
    PVOID AllocationBase,
    SIZE_T AllocationSize);

typedef struct _RTL_VERIFIER_PROVIDER_DESCRIPTOR {
    ULONG Length;
    PRTL_VERIFIER_DLL_DESCRIPTOR ProviderDlls;
    RTL_VERIFIER_DLL_LOAD_CALLBACK ProviderDllLoadCallback;
    RTL_VERIFIER_DLL_UNLOAD_CALLBACK ProviderDllUnloadCallback;

    PWSTR VerifierImage;
    ULONG VerifierFlags;
    ULONG VerifierDebug;

    PVOID RtlpGetStackTraceAddress;
    PVOID RtlpDebugPageHeapCreate;
    PVOID RtlpDebugPageHeapDestroy;

    RTL_VERIFIER_NTDLLHEAPFREE_CALLBACK ProviderNtdllHeapFreeCallback;
} RTL_VERIFIER_PROVIDER_DESCRIPTOR;

RTL_VERIFIER_DLL_DESCRIPTOR noHooks{};
RTL_VERIFIER_PROVIDER_DESCRIPTOR desc = {
    sizeof(desc),
    &noHooks,
    [](auto, auto, auto, auto) {},
    [](auto, auto, auto, auto) {},
    nullptr, 0, 0,
    nullptr, nullptr, nullptr,
    [](auto, auto) {},
};
//

void NTAPI WaitForWh(LPVOID pParam1, LPVOID pParam2, LPVOID pParam3) {
    PTEB teb = (PTEB)NtCurrentTeb();
    PPEB peb = teb->ProcessEnvironmentBlock;
    PPEB_LDR_DATA ldr = peb->Ldr;
    PLIST_ENTRY moduleList = &ldr->InLoadOrderModuleList;
    PLIST_ENTRY currentEntry = moduleList->Flink;

    //
    // Since we do not link against kernel32, we have to wait for some
    // other part of the application to call it in; here, we continously
    // parse the PEB and check whether kernelbase is finally loaded.
    //
    HMODULE hKernelBase = nullptr;
    while (currentEntry != moduleList) {
        PLDR_DATA_TABLE_ENTRY currentModule = CONTAINING_RECORD(currentEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        wchar_t name[MAX_PATH];
        //
        // All wcs* functions here are intrinsic (don't require the CRT).
        //
        if (wcslen(currentModule->BaseDllName.Buffer) < MAX_PATH - 1) {
            wcscpy(name, currentModule->BaseDllName.Buffer);
            for (wchar_t* p = name; *p != L'\0'; ++p) if (p[0] >= L'A' && p[0] <= L'Z') p[0] += (L'a' - L'A');
            if (!wcscmp(name, L"kernelbase.dll")) {
                hKernelBase = reinterpret_cast<HMODULE>(currentModule->DllBase);
            }
        }
        currentEntry = currentEntry->Flink;
    }

    //
    // When unable to locate kernelbase, schedule a retry for later.
    //
    if (!hKernelBase) NtQueueApcThread(NtCurrentThread(), reinterpret_cast<PPS_APC_ROUTINE>(WaitForWh), 0, 0, 0);
    else {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hKernelBase;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hKernelBase + dosHeader->e_lfanew);

        DWORD exportDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hKernelBase + exportDirRVA);

        DWORD* nameRVAs = (DWORD*)((BYTE*)hKernelBase + exportDir->AddressOfNames);
        WORD* ordinals = (WORD*)((BYTE*)hKernelBase + exportDir->AddressOfNameOrdinals);
        DWORD* funcRVAs = (DWORD*)((BYTE*)hKernelBase + exportDir->AddressOfFunctions);

        //
        // Now that we have kernelbase.dll, find CreateProcessInternalW in it,
        // which Windhawk patches - this is how we know it successfully 
        // injected and patched. GetProcAddress could be used instead, but
        // we can also continue parsing the PEB and locating the address 
        // manually
        //
        PVOID pCreateProcessInternalW = nullptr;
        for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
            const char* functionName = (const char*)((BYTE*)hKernelBase + nameRVAs[i]);
            WORD ordinal = ordinals[i];
            DWORD funcRVA = funcRVAs[ordinal];
            PVOID funcAddress = (BYTE*)hKernelBase + funcRVA;
            //
            // memcmp is intrinsi (it will be inlined), but compiles so only
            // when the string to check against is up to 18 characters long, 
            // so we need this "hack" (for some reason, strcmp doesn't work 
            // as intrinsic on my compiler, despite the documentation 
            // claiming so).
            //
            if (!memcmp(functionName, "CreateProcessInter", 18) && !memcmp(functionName + 18, "nalW", 5)) {
                pCreateProcessInternalW = funcAddress;
                break;
            }
        }
        if (pCreateProcessInternalW) {
            //
            // Instead of using GetTickCount64(), we can obtain the tick count
            // directly from the KUSER_SHARED_DATA structure that the kernel
            // maps into every processes' address space at 0x7ffe0000.
            //
            auto GetTickCount64 = []() { return (ULONGLONG)((*(ULONGLONG*)0x7ffe0320 * (ULONGLONG)(*(DWORD*)0x7ffe0004)) >> 24); };
            //
            // Busy wait here, waiting for Windhawk to install its patches
            //
            auto start = GetTickCount64();
            while (true) {
                //
                // This is key here: allow APCs scheduled to this thread to
                // execute while we busy wait here
                //
                NtAlertThread(NtCurrentThread());
                if (*(BYTE*)pCreateProcessInternalW == 0xE9) {
                    //
                    // Windhawk has installed its patches, so we can exit
                    // from here and resume normal program execution (the
                    // real entry point finally gets a chance to execute)
                    //
                    break;
                }
                else if (GetTickCount64() - start > 1000) {
                    //
                    // If Windhawk hasn't patched in 1000ms after we signaled
                    // it, we presume it is dead/crashed/was unable to
                    // inject, so simply give up
                    //
                    break;
                }
            }
        }
    }
}

BOOL NTAPI DllMain(_In_ HINSTANCE Instance, _In_ DWORD Reason, _In_ PVOID lpReserved) {
    if (Reason == DLL_PROCESS_ATTACH) {
        //
        // Native API equivalent to DisableThreadLibraryCalls() - disables
        // DllMain notifications when a thread is created or destroyed.
        //
        LdrDisableThreadCalloutsForDll(Instance);
        //
        // Here, we obtain a handle to an event Windhawk is waiting on;
        // when signaled, Windhawk will begin right away scanning for
        // and injecting new processes, instead of waiting for the default
        // up to 1000ms timeout.
        //
        UNICODE_STRING wszEventName;
        RtlInitUnicodeString(&wszEventName, L"\\BaseNamedObjects\\Global\\WindhawkScanForProcesses");
        OBJECT_ATTRIBUTES oa{};
        InitializeObjectAttributes(&oa, &wszEventName, 0, nullptr, nullptr);
        HANDLE hEvent = nullptr;
        NtOpenEvent(&hEvent, EVENT_MODIFY_STATE, &oa);
        if (hEvent && hEvent != INVALID_HANDLE_VALUE) {
            NtSetEvent(hEvent, nullptr);
            //
            // Schedule an APC in which we wait for Windhawk to inject this
            // process - a new thread should be created eventually which
            // will load Windhawk's DLL (Windhawk won't queue an APC on this
            // thread because the program is already executing).
            // 
            // Using an APC here is mandatory since spinlocking here instead
            // would keep holding the library load lock (that we currently own
            // when being here), which would make others, including
            // Windhawk, unable to inject their own libraries. Instead, we
            // schedule this "readiness" check for later on, allowing others
            // to load their libraries as well further on.
            //
            NtQueueApcThread(NtCurrentThread(), reinterpret_cast<PPS_APC_ROUTINE>(WaitForWh), 0, 0, 0);
            NtClose(hEvent);
        }
    }
    else if (Reason == DLL_PROCESS_VERIFIER) {
        //
        // This gets called when the library is injected as a verifier
        // engine DLL; simply returning here is not enough, we have to feed
        // the main verifier engine a structure that specifies what our
        // library expects; we return stubs here, since we do not want to
        // hook anything, we are fine just injected in the target executable.
        //
        *(PVOID*)lpReserved = &desc;
    }
    return true;
}
