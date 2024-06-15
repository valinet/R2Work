// Example application for Windhawk early injection testing
// ==========================================================================
// Valentin-Gabriel Radu, valentin.radu@valinet.ro
//
// Upstream issue:
//    https://github.com/ramensoftware/windhawk/issues/197
//
#include <Windows.h>
#include <winnetwk.h>
#pragma comment(lib, "mpr.lib")
#include <TlHelp32.h>

EXTERN_C IMAGE_DOS_HEADER __ImageBase;
#define HINST_THISCOMPONENT ((HINSTANCE)&__ImageBase)

#define SERVICE_NAME L"R2Service"

SERVICE_STATUS        g_ServiceStatus = { };
SERVICE_STATUS_HANDLE g_StatusHandle = nullptr;
bool                  g_IsWindhawkInjected = false;

// https://stackoverflow.com/questions/4023586/correct-way-to-find-out-if-a-service-is-running-as-the-system-user
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

DWORD WINAPI ServiceWorkerThread(LPVOID lpParam) {
	wchar_t wszPath[MAX_PATH];
	GetWindowsDirectoryW(wszPath, MAX_PATH);
	wchar_t wszCommand[MAX_PATH]{};
	wszCommand[0] = L'\"';
	auto len = GetModuleFileNameW(HINST_THISCOMPONENT, wszCommand + 1, MAX_PATH);
	if (len > 0) {
		wszCommand[len + 1] = L'\"';
		//
		// When service is injected successfully early on, report this to
		// child so that it displays a notification in the message box
		//
		if (g_IsWindhawkInjected) {
			wszCommand[len + 2] = L' ';
			wszCommand[len + 3] = L'1';
		}
		HANDLE procInteractiveWinlogon = INVALID_HANDLE_VALUE;
		PROCESSENTRY32 entry;
		entry.dwSize = sizeof(PROCESSENTRY32);
		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hSnapshot) {
			if (Process32First(hSnapshot, &entry) == TRUE) {
				DWORD dwActiveSessionId = WTSGetActiveConsoleSessionId();
				while (Process32Next(hSnapshot, &entry) == TRUE) {
					if (!_wcsicmp(entry.szExeFile, L"winlogon.exe")) {
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
		if (tknInteractive && tknInteractive != INVALID_HANDLE_VALUE) {
			PROCESS_INFORMATION pi{};
			STARTUPINFO si{};
			si.cb = sizeof(si);
			si.lpDesktop = (LPWSTR)L"WinSta0\\Default";
			CreateProcessAsUserW(tknInteractive, nullptr, wszCommand, nullptr, nullptr, false, INHERIT_CALLER_PRIORITY, nullptr, nullptr, &si, &pi);
			if (pi.hThread) CloseHandle(pi.hThread);
			if (pi.hProcess) CloseHandle(pi.hProcess);
			CloseHandle(tknInteractive);
		}
	}
	return 0;
}

unsigned long WINAPI ServiceCtrlHandlerEx(DWORD dwControl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext) {
	switch (dwControl) {
	case SERVICE_CONTROL_STOP:
		if (g_ServiceStatus.dwCurrentState != SERVICE_RUNNING) break;
		g_ServiceStatus.dwControlsAccepted = 0;
		g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
		g_ServiceStatus.dwWin32ExitCode = 0;
		g_ServiceStatus.dwCheckPoint = 4;
		SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
		break;
	default:
		break;
	}
	return NO_ERROR;
}

void WINAPI ServiceMain(DWORD argc,	LPTSTR* argv) {
	//
	// Code that runs when the app is run as a service
	//
	// Register service with the SCM
	//
	g_StatusHandle = RegisterServiceCtrlHandlerExW(SERVICE_NAME, &ServiceCtrlHandlerEx, nullptr);
	if (g_StatusHandle == NULL) return;
	//
	// Set service status: "Start Pending"
	//
	g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
	g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
	g_ServiceStatus.dwWin32ExitCode = NO_ERROR;
	g_ServiceStatus.dwServiceSpecificExitCode = 0;
	g_ServiceStatus.dwCheckPoint = 1;
	SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
	//
	// Create worker thread which will start this executable as a regular
	// app on the user's desktop
	//
	HANDLE hThread = CreateThread(nullptr, 0, &ServiceWorkerThread, nullptr, 0, nullptr);
	if (hThread == nullptr || hThread == INVALID_HANDLE_VALUE) {
		g_ServiceStatus.dwControlsAccepted = 0;
		g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
		g_ServiceStatus.dwWin32ExitCode = GetLastError();
		g_ServiceStatus.dwCheckPoint = 2;
		SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
		return;
	}
	//
	// Thread is running, so let's report that via SCM as "Status: Running"
	//
	g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
	g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
	g_ServiceStatus.dwWin32ExitCode = 0;
	g_ServiceStatus.dwCheckPoint = 3;
	SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
	//
	// Wait for thread to start the app on the user's desktop (should be very fast)
	//
	WaitForSingleObject(hThread, INFINITE);
	//
	// Wait a bit so that the SCM GUI does not display a warning message saying
	// that the service started and that it immediatly stopped
	//
	Sleep(2000); 
	//
	// Stop the service, we are done
	//
	g_ServiceStatus.dwControlsAccepted = 0;
	g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
	g_ServiceStatus.dwWin32ExitCode = 0;
	g_ServiceStatus.dwCheckPoint = 5;
	SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

INT WINAPI ApplicationMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, INT nCmdShow) {
	//
	// Code that runs when the app is run normally, NOT as a service
	//
	SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
	if (MessageBoxW(FindWindowW(L"Shell_TrayWnd", nullptr), 
		__argc > 1 ? L"Do you want to map a new network drive?\n\nPS. CreateProcessInternalW seems to have been injected in the service that started me as well." : L"Do you want to map a new network drive?", 
		IsLocalSystem() ? L"Started from a service" : L"Started from the desktop", 
		MB_ICONINFORMATION | MB_OK) == IDYES) {
		WNetConnectionDialog(nullptr, RESOURCETYPE_DISK);
	}
	return 0;
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
	//
	// Record successful Windhawk injection
	//
	HMODULE hKernelBase = GetModuleHandleW(L"kernelbase.dll");
	if (hKernelBase) {
		FARPROC pCreateProcessInternalW = GetProcAddress(hKernelBase, "CreateProcessInternalW");
		g_IsWindhawkInjected = (pCreateProcessInternalW && *(BYTE*)pCreateProcessInternalW == 0xE9);
	}
	SERVICE_TABLE_ENTRY ServiceTable[] =
	{
		{(LPWSTR)SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)ServiceMain},
		{NULL, NULL}
	};
	if (StartServiceCtrlDispatcherW(ServiceTable) == FALSE) {
		return ApplicationMain(hInstance, hPrevInstance, pCmdLine, nCmdShow);
	}
	return 0;
}
