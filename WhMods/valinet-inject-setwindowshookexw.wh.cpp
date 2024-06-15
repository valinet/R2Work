// ==WindhawkMod==
// @id              valinet-inject-setwindowshookexw
// @name            Inject using SetWindowsHookExW
// @description     Inject using SetWindowsHookExW
// @version         0.1
// @author          valinet
// @github          https://github.com/valinet
// @include         windhawk.exe
// ==/WindhawkMod==

// ==WindhawkModReadme==
/*
# Inject using SetWindowsHookExW
Inject using SetWindowsHookExW
*/
// ==/WindhawkModReadme==

#include <debugapi.h>
#include <errhandlingapi.h>
#include <handleapi.h>
#include <libloaderapi.h>
#include <processthreadsapi.h>
#include <thread>
#include <psapi.h>
#include <synchapi.h>
#include <sysinfoapi.h>
#include <tlhelp32.h>
#include <hidsdi.h>
#include <winerror.h>
#include <winnt.h>

//#define Wh_Log_External
//#define Wh_Log_Original
#define Wh_Log_External OutputDebugString
#define Wh_Log_Original Wh_Log

#define QWORD INT64

EXTERN_C IMAGE_DOS_HEADER __ImageBase;
#define HINST_THISCOMPONENT ((HINSTANCE)&__ImageBase)

BOOL IsLocalSystem() {
    HANDLE hToken;
    UCHAR bTokenUser[sizeof(TOKEN_USER) + 8 + 4 * SID_MAX_SUB_AUTHORITIES];
    PTOKEN_USER pTokenUser = (PTOKEN_USER)bTokenUser;
    ULONG cbTokenUser;
    SID_IDENTIFIER_AUTHORITY siaNT = SECURITY_NT_AUTHORITY;
    PSID pSystemSid;
    BOOL bSystem;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) return FALSE;
    if (!GetTokenInformation(hToken, TokenUser, pTokenUser, sizeof(bTokenUser), &cbTokenUser)) {
        CloseHandle(hToken);
        return FALSE;
    }
    CloseHandle(hToken);
    if (!AllocateAndInitializeSid(&siaNT, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &pSystemSid)) return FALSE;
    bSystem = EqualSid(pTokenUser->User.Sid, pSystemSid);
    FreeSid(pSystemSid);
    return bSystem;
}

LRESULT CALLBACK HookProc(int nCode, WPARAM wParam, LPARAM lParam) {
    return CallNextHookEx(nullptr, nCode, wParam, lParam);
}

extern "C" int procMain(HWND hWnd, HINSTANCE hInstance, LPSTR lpszCmdLine, int nCmdShow) {
    BOOL amI32Bit = FALSE;
    IsWow64Process(GetCurrentProcess(), &amI32Bit);
    int dwBitness = amI32Bit ? 32 : 64;

    DWORD dwSessionId = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &dwSessionId);

    wchar_t wszName[MAX_PATH];
    swprintf_s(wszName, L"Global\\{AD86EF85-1D72-466F-B9BB-08E8BA96884D}_%d_%d", dwSessionId, dwBitness);

    SECURITY_DESCRIPTOR sd;
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, true, nullptr, false);
    SECURITY_ATTRIBUTES sa = { };
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = false;
    sa.lpSecurityDescriptor = &sd;
    SetLastError(ERROR_SUCCESS);
    HANDLE evCtrl = CreateEventW(&sa, false, false, wszName);
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(evCtrl);
        return ERROR_ALREADY_EXISTS;
    }

    MSG msg;
    PeekMessageW(&msg, nullptr, 0, 0, PM_NOREMOVE);
    wchar_t wszMsg[MAX_PATH * 4];

    SetLastError(ERROR_SUCCESS);
    HHOOK hHook = SetWindowsHookExW(WH_SHELL, &HookProc, HINST_THISCOMPONENT, 0);
    swprintf_s(wszMsg, L"%d_%d : SetWindowsHookExW: %d (%d)\n", dwSessionId, dwBitness, hHook, GetLastError());
    Wh_Log_External(wszMsg);

    while (true) {
        bool isQuiting = false;
        auto rv = MsgWaitForMultipleObjects(1, &evCtrl, false, INFINITE, QS_ALLINPUT);
        if (rv != WAIT_OBJECT_0 + 1) break;
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT) {
                isQuiting = true;
                break;
            }
            else {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
        if (isQuiting) break;
    }

    if (hHook) UnhookWindowsHookEx(hHook);
    if (evCtrl) CloseHandle(evCtrl);
    return ERROR_SUCCESS;
}

HANDLE mutSingleInstance = nullptr;
std::vector<HANDLE> processes;

BOOL Wh_ModInit() {
    bool isSystemAccount = IsLocalSystem();
    if (isSystemAccount) {
        SECURITY_DESCRIPTOR sd;
        InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
        SetSecurityDescriptorDacl(&sd, true, nullptr, false);
        SECURITY_ATTRIBUTES sa = { };
        sa.nLength = sizeof(sa);
        sa.bInheritHandle = false;
        sa.lpSecurityDescriptor = &sd;
        SetLastError(ERROR_SUCCESS);
        mutSingleInstance = CreateEventW(&sa, false, false, L"Global\\{A50409A9-A5BB-439B-9B4F-912539954800}");
        if (GetLastError() == ERROR_ALREADY_EXISTS) {
            CloseHandle(mutSingleInstance);
            mutSingleInstance = nullptr;
        }
        if (mutSingleInstance && mutSingleInstance != INVALID_HANDLE_VALUE) {
            for (auto i = 0; i < 10; ++i) YieldProcessor();
            std::vector<std::wstring> bitnesses;
            bitnesses.push_back(L"64");
            bitnesses.push_back(L"32");
            std::vector<int> sessions;
            sessions.push_back(0);
            sessions.push_back(WTSGetActiveConsoleSessionId());
            for (auto& bitness : bitnesses) {
                for (auto& session : sessions) {
                    wchar_t wszPath[MAX_PATH];
                    GetWindowsDirectory(wszPath, MAX_PATH);
                    wchar_t wszArguments[MAX_PATH]{};
                    GetModuleFileNameW(HINST_THISCOMPONENT, wszArguments, MAX_PATH);
                    BOOL amI32Bit = FALSE;
                    IsWow64Process(GetCurrentProcess(), &amI32Bit);
                    for (wchar_t* p = wszArguments; *p != L'\0'; p++) if (amI32Bit ? (p[0] == L'3' && p[1] == L'2') : (p[0] == L'6' && p[1] == L'4')) { p[0] = bitness[0]; p[1] = bitness[1]; }
                    wchar_t wszCommand[MAX_PATH * 3];
                    if (amI32Bit) swprintf_s(wszCommand, L"\"%s\\%s\\rundll32.exe\" %s,procMain", wszPath, (bitness == L"32" ? L"System32" : L"Sysnative"), wszArguments);
                    else swprintf_s(wszCommand, L"\"%s\\%s\\rundll32.exe\" %s,procMain", wszPath, (bitness == L"32" ? L"SysWOW64" : L"System32"), wszArguments);
                    Wh_Log_Original(L"%s\n", wszCommand);
                    if (session == 0) {
                        PROCESS_INFORMATION pi{};
                        STARTUPINFO si{};
                        si.cb = sizeof(si);
                        si.lpDesktop = (LPWSTR)L"WinSta0\\Default";
                        CreateProcessW(nullptr, wszCommand, nullptr, nullptr, false, INHERIT_CALLER_PRIORITY,  nullptr, nullptr, &si, &pi);
                        if (pi.hThread) CloseHandle(pi.hThread);
                        if (pi.hProcess) processes.push_back(pi.hProcess);
                    } else {
                        HANDLE procInteractiveWinlogon = INVALID_HANDLE_VALUE;
                        PROCESSENTRY32 entry;
                        entry.dwSize = sizeof(PROCESSENTRY32);
                        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                        if (hSnapshot) {
                            if (Process32First(hSnapshot, &entry) == TRUE) {
                                DWORD dwActiveSessionId = WTSGetActiveConsoleSessionId();
                                while (Process32Next(hSnapshot, &entry) == TRUE) {
                                    if (!wcsicmp(entry.szExeFile, L"winlogon.exe")) {
                                        DWORD dwWinLogonSessionId = -1;
                                        ProcessIdToSessionId(entry.th32ProcessID, &dwWinLogonSessionId);
                                        if (dwActiveSessionId == dwWinLogonSessionId) {
                                            if ((procInteractiveWinlogon = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ProcessID))) {
                                                BOOL bIs32Bit = FALSE;
                                                if (!IsWow64Process(procInteractiveWinlogon, &bIs32Bit) || bIs32Bit) {
                                                    CloseHandle(procInteractiveWinlogon);
                                                    procInteractiveWinlogon = INVALID_HANDLE_VALUE;
                                                    continue;
                                                }
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                            CloseHandle(hSnapshot);
                        }
                        Wh_Log_Original(L"procInteractiveWinlogon: %p\n", procInteractiveWinlogon);
                        HANDLE tknInteractive = INVALID_HANDLE_VALUE;
                        if (procInteractiveWinlogon && procInteractiveWinlogon != INVALID_HANDLE_VALUE) {
                            HANDLE tknWinlogon = INVALID_HANDLE_VALUE;
                            if (OpenProcessToken(procInteractiveWinlogon, TOKEN_DUPLICATE, &tknWinlogon) && tknWinlogon && tknWinlogon != INVALID_HANDLE_VALUE) {
                                SECURITY_ATTRIBUTES tokenAttributes;
                                ZeroMemory(&tokenAttributes, sizeof(SECURITY_ATTRIBUTES));
                                tokenAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
                                DuplicateTokenEx(tknWinlogon, 0x10000000, &tokenAttributes, SecurityImpersonation, TokenImpersonation, &tknInteractive);
                                CloseHandle(tknWinlogon);
                            }
                            CloseHandle(procInteractiveWinlogon);
                        }
                        Wh_Log_Original(L"tknInteractive: %p\n", tknInteractive);
                        if (tknInteractive && tknInteractive != INVALID_HANDLE_VALUE) {
                            PROCESS_INFORMATION pi{};
                            STARTUPINFO si{};
                            si.cb = sizeof(si);
                            si.lpDesktop = (LPWSTR)L"WinSta0\\Default";
                            CreateProcessAsUserW(tknInteractive, nullptr, wszCommand, nullptr, nullptr, false, INHERIT_CALLER_PRIORITY,  nullptr, nullptr, &si, &pi);
                            if (pi.hThread) CloseHandle(pi.hThread);
                            if (pi.hProcess) processes.push_back(pi.hProcess);
                            CloseHandle(tknInteractive);
                        }
                    }
                }
            }
        }
    }
    Wh_Log_Original(L"Init %d\n", isSystemAccount);
    return TRUE;
}

void Wh_ModUninit() {
    for (auto& process : processes) {
        BOOL is32Bit = FALSE;
        IsWow64Process(process, &is32Bit);

        DWORD dwSessionId = 0;
        ProcessIdToSessionId(GetProcessId(process), &dwSessionId);

        wchar_t wszName[MAX_PATH];
        swprintf_s(wszName, L"Global\\{AD86EF85-1D72-466F-B9BB-08E8BA96884D}_%d_%d", dwSessionId, is32Bit ? 32 : 64);

        HANDLE evCtrl = OpenEventW(EVENT_MODIFY_STATE, false, wszName);
        if (evCtrl) {
            SetEvent(evCtrl);
            CloseHandle(evCtrl);
        }
        
        WaitForSingleObject(process, INFINITE);
        DWORD dwExitCode = 1;
        GetExitCodeProcess(process, &dwExitCode);
        Wh_Log_Original(L"Exited process with %d.\n", dwExitCode);
        CloseHandle(process);
    }
    if (mutSingleInstance) CloseHandle(mutSingleInstance);
    Wh_Log_Original(L"Uninit");
}

void Wh_ModSettingsChanged() {
    Wh_Log_Original(L"SettingsChanged");
}

BOOL APIENTRY DllMain(_In_ HINSTANCE Instance, _In_ DWORD Reason, _In_ LPVOID Reserved) {
	if (Reason == DLL_PROCESS_ATTACH) {
		DisableThreadLibraryCalls(Instance);
		HANDLE hEvent = OpenEventW(EVENT_MODIFY_STATE, false, L"Global\\WindhawkScanForProcesses");
		if (hEvent) {
			SetEvent(hEvent);
			HMODULE hKernelBase = GetModuleHandleW(L"kernelbase.dll");
			if (hKernelBase) {
				FARPROC pCreateProcessInternalW = GetProcAddress(hKernelBase, "CreateProcessInternalW");
				if (pCreateProcessInternalW) {
					auto GetMyTickCount64 = []() { return (ULONGLONG)((*(ULONGLONG*)0x7ffe0320 * (ULONGLONG)(*(DWORD*)0x7ffe0004)) >> 24); };
					auto start = GetMyTickCount64();
					while (true) {
						SleepEx(0, true);
						if (*(BYTE*)pCreateProcessInternalW == 0xE9 || (GetMyTickCount64() - start > 1000)) break;
					}
				}
			}
			CloseHandle(hEvent);
		}
	}
	return true;
}
