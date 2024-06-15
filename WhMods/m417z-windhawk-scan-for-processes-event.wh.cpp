// ==WindhawkMod==
// @id              windhawk-scan-for-processes-event
// @name            WindhawkScanForProcesses
// @description     An event for Windhawk to scan for new processes
// @version         1.0
// @author          m417z
// @github          https://github.com/m417z
// @twitter         https://twitter.com/m417z
// @homepage        https://m417z.com/
// @include         windhawk.exe
// ==/WindhawkMod==

#include <sddl.h>
#include <synchapi.h>
#include <windhawk_api.h>

#include <algorithm>

constexpr WCHAR kScanForProcessesEventName[] = L"Global\\WindhawkScanForProcesses";
constexpr WCHAR kScanForProcessesDoneEventName[] = L"Global\\WindhawkScanForProcessesDone";

HANDLE g_scanForProcessesEvent = nullptr;
HANDLE g_scanForProcessesDoneEvent = nullptr;
bool g_signaled = false;

HANDLE CreateEventForMediumIntegrity(PCWSTR eventName, BOOL manualReset) {
    // Allow only EVENT_MODIFY_STATE (0x0002), only for medium integrity.
    PCWSTR pszStringSecurityDescriptor = L"D:(A;;0x0002;;;WD)S:(ML;;NW;;;ME)";

    HLOCAL secDesc;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptor(
            pszStringSecurityDescriptor, SDDL_REVISION_1, &secDesc, nullptr)) {
        return nullptr;
    }

    SECURITY_ATTRIBUTES secAttr = {sizeof(SECURITY_ATTRIBUTES)};
    secAttr.lpSecurityDescriptor = secDesc;
    secAttr.bInheritHandle = FALSE;

    HANDLE event = CreateEvent(&secAttr, manualReset, FALSE, eventName);

    LocalFree(secDesc);

    return event;
}

using WaitForMultipleObjectsEx_t = decltype(&WaitForMultipleObjectsEx);
WaitForMultipleObjectsEx_t WaitForMultipleObjectsEx_Original;
DWORD WINAPI WaitForMultipleObjectsEx_Hook(DWORD nCount,
                                           CONST HANDLE* lpHandles,
                                           WINBOOL bWaitAll,
                                           DWORD dwMilliseconds,
                                           WINBOOL bAlertable) {
    if (g_signaled) {
        SetEvent(g_scanForProcessesDoneEvent);
        g_signaled = false;
    }

    void* retAddress = __builtin_return_address(0);

    auto original = [&]() {
        return WaitForMultipleObjectsEx_Original(nCount, lpHandles, bWaitAll,
                                                 dwMilliseconds, bAlertable);
    };

    HMODULE module;
    if (!GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                               GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (PCWSTR)retAddress, &module) ||
        module != GetModuleHandle(nullptr)) {
        return original();
    }

    Wh_Log(L">");

    if (nCount >= 10 || bWaitAll) {
        return original();
    }

    HANDLE handles[10];
    std::copy(lpHandles, lpHandles + nCount, handles);
    handles[nCount] = g_scanForProcessesEvent;

    lpHandles = handles;
    nCount++;

    DWORD ret = WaitForMultipleObjectsEx_Original(nCount, lpHandles, bWaitAll,
                                                  dwMilliseconds, bAlertable);
    if (ret == WAIT_OBJECT_0 + nCount - 1) {
        Wh_Log(L"Got WindhawkScanForProcesses event");
        g_signaled = true;
        ret = WAIT_TIMEOUT;
    }

    return ret;
}

BOOL Wh_ModInit() {
    Wh_Log(L">");

    bool serviceProcess = false;

    int argc;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLine(), &argc);
    if (!argv) {
        Wh_Log(L"CommandLineToArgvW failed");
        return FALSE;
    }

    for (int i = 1; i < argc; i++) {
        if (wcscmp(argv[i], L"-service") == 0) {
            serviceProcess = true;
            break;
        }
    }

    LocalFree(argv);

    if (!serviceProcess) {
        return FALSE;
    }

    g_scanForProcessesEvent =
        CreateEventForMediumIntegrity(kScanForProcessesEventName, FALSE);
    if (!g_scanForProcessesEvent) {
        Wh_Log(L"CreateEvent failed");
        return FALSE;
    }

    g_scanForProcessesDoneEvent =
        CreateEventForMediumIntegrity(kScanForProcessesDoneEventName, FALSE);
    if (!g_scanForProcessesDoneEvent) {
        Wh_Log(L"CreateEvent failed");
        return FALSE;
    }
    SetEvent(g_scanForProcessesDoneEvent);

    if (!Wh_SetFunctionHook((void*)WaitForMultipleObjectsEx,
                            (void*)WaitForMultipleObjectsEx_Hook,
                            (void**)&WaitForMultipleObjectsEx_Original)) {
        return FALSE;
    }

    return TRUE;
}

void Wh_ModUninit() {
    Wh_Log(L">");

    if (WaitForMultipleObjectsEx_Original) {
        Wh_RemoveFunctionHook((void*)WaitForMultipleObjectsEx);
    }
    if (g_scanForProcessesEvent) {
        CloseHandle(g_scanForProcessesEvent);
    }
    if (g_scanForProcessesDoneEvent) {
        CloseHandle(g_scanForProcessesDoneEvent);
    }
}
