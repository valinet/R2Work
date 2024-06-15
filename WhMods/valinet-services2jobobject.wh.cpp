// ==WindhawkMod==
// @id              valinet-services2jobobject
// @name            services2job
// @description     Attempt to add services.exe to job object
// @version         0.1
// @author          valinet
// @github          https://github.com/valinet
// @include         windhawk.exe
// ==/WindhawkMod==

// ==WindhawkModReadme==
/*
# services2jobobject
Attempt to add services.exe to job object
*/
// ==/WindhawkModReadme==

#include <debugapi.h>
#include <handleapi.h>
#include <jobapi.h>
#include <libloaderapi.h>
#include <processthreadsapi.h>
#include <thread>
#include <psapi.h>
#include <synchapi.h>
#include <sysinfoapi.h>
#include <tlhelp32.h>
#include <hidsdi.h>
#include <winerror.h>

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

HANDLE hJobObject = nullptr;

BOOL Wh_ModInit() {
    bool isSystemAccount = IsLocalSystem();
    if (isSystemAccount) {
        hJobObject = CreateJobObjectW(nullptr, nullptr);
        if (hJobObject && hJobObject != INVALID_HANDLE_VALUE) {
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli{};
            jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_BREAKAWAY_OK;
            if (SetInformationJobObject(hJobObject, JobObjectExtendedLimitInformation, reinterpret_cast<LPVOID>(&jeli), sizeof(jeli))) {
                wchar_t wszPath[MAX_PATH];
                GetWindowsDirectory(wszPath, MAX_PATH);
                wchar_t wszArguments[MAX_PATH]{};
                GetModuleFileNameW(HINST_THISCOMPONENT, wszArguments, MAX_PATH);
                wchar_t wszCommand[MAX_PATH * 3];
                BOOL amI32Bit = FALSE;
                if (!IsWow64Process(GetCurrentProcess(), &amI32Bit) || amI32Bit) swprintf_s(wszCommand, L"\"%s\\SysWOW64\\rundll32.exe\" %s,procMain", wszPath, wszArguments);
                else swprintf_s(wszCommand, L"\"%s\\System32\\rundll32.exe\" %s,procMain", wszPath, wszArguments);
                Wh_Log_Original(L"%s\n", wszCommand);
                HANDLE procInteractiveWinlogon = INVALID_HANDLE_VALUE;
                PROCESSENTRY32 entry;
                entry.dwSize = sizeof(PROCESSENTRY32);
                HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                if (hSnapshot) {
                    if (Process32First(hSnapshot, &entry) == TRUE) {
                        //DWORD dwActiveSessionId = WTSGetActiveConsoleSessionId();
                        while (Process32Next(hSnapshot, &entry) == TRUE) {
                            if (!wcsicmp(entry.szExeFile, L"services.exe")) {
                                DWORD dwWinLogonSessionId = -1;
                                ProcessIdToSessionId(entry.th32ProcessID, &dwWinLogonSessionId);
                                if (0 == dwWinLogonSessionId) {
                                    if ((procInteractiveWinlogon = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_QUOTA | PROCESS_TERMINATE, FALSE, entry.th32ProcessID))) {
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
                    BOOL isinJob = false;
                    bool isinJobOk = IsProcessInJob(procInteractiveWinlogon, nullptr, &isinJob);
                    Wh_Log_Original(L"IsProcessInJob: %d %d\n", isinJobOk, isinJob);
                    if (isinJobOk && !isinJobOk) {
                        Wh_Log_Original(L"IsProcessInJob: %d\n", AssignProcessToJobObject(hJobObject, procInteractiveWinlogon));
                    }
                    isinJobOk = IsProcessInJob(procInteractiveWinlogon, nullptr, &isinJob);
                    Wh_Log_Original(L"IsProcessInJob: %d %d\n", isinJobOk, isinJob);
                    CloseHandle(procInteractiveWinlogon);
                }
                Wh_Log_Original(L"tknInteractive: %p\n", tknInteractive);
                if (tknInteractive && tknInteractive != INVALID_HANDLE_VALUE) {
                    CloseHandle(tknInteractive);
                }
            }
        }
    }
    Wh_Log_Original(L"Init %d\n", isSystemAccount);
    return TRUE;
}

void Wh_ModUninit() {
    if (hJobObject && hJobObject != INVALID_HANDLE_VALUE) CloseHandle(hJobObject);
    Wh_Log_Original(L"Uninit");
}

void Wh_ModSettingsChanged() {
    Wh_Log_Original(L"SettingsChanged");
}
