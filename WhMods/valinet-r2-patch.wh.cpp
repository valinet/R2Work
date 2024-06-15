// ==WindhawkMod==
// @id              valinet-r2patch
// @name            R2Patch
// @description     Demo patch for R2 Service
// @version         0.1
// @author          valinet
// @github          https://github.com/valinet
// @include         r2service.exe
// ==/WindhawkMod==

// ==WindhawkModReadme==
/*
# R2Patch
Demo patch for R2 Service
*/
// ==/WindhawkModReadme==

int(*MessageBoxWFunc)(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType);
int MessageBoxWHook(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType) {
    Wh_Log(L"MessageBoxWHook");
    return MessageBoxWFunc(hWnd, lpText, lpCaption, uType | MB_YESNO);
}

BOOL Wh_ModInit() {
#ifdef _WIN64
    const size_t OFFSET_SAME_TEB_FLAGS = 0x17EE;
#else
    const size_t OFFSET_SAME_TEB_FLAGS = 0x0FCA;
#endif
    bool isInitialThread = *(USHORT*)((BYTE*)NtCurrentTeb() + OFFSET_SAME_TEB_FLAGS) & 0x0400;
    Wh_Log(L"Init: %d\n", isInitialThread);
    Wh_SetFunctionHook(reinterpret_cast<void*>(&MessageBoxW), reinterpret_cast<void*>(&MessageBoxWHook), reinterpret_cast<void**>(&MessageBoxWFunc));
    return TRUE;
}

void Wh_ModUninit() {
    if (MessageBoxWFunc) Wh_RemoveFunctionHook(reinterpret_cast<void*>(&MessageBoxW));
    Wh_Log(L"Uninit");
}

void Wh_ModSettingsChanged() {
    Wh_Log(L"SettingsChanged");
}
