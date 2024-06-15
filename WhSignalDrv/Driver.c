// Example of a driver that helps Windhawk
// inject processes created by inaccessible processes early on
// ==========================================================================
// Valentin-Gabriel Radu, valentin.radu@valinet.ro
//
// Upstream issue:
//    https://github.com/ramensoftware/windhawk/issues/197
//
#include <ntifs.h>
#define INVALID_HANDLE_VALUE ((HANDLE)(LONG_PTR)-1)
//#define WITH_WAIT_FOR_CONFIRMATION
//#define WITH_DBGPRINT

#ifdef WITH_WAIT_FOR_CONFIRMATION
UINT64 dwDefaultTimeoutMs = 1000;
UINT64 dwTimeoutMs = 1000;
#endif
UINT64 bRegisteredRoutine = FALSE;

void CreateProcessNotifyRoutine(_Inout_ PEPROCESS Process, _In_ HANDLE ProcessId, _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo) {
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(CreateInfo);
    NTSTATUS rv = STATUS_SUCCESS;
#ifdef WITH_DBGPRINT
    DbgPrint("WhSignalDrv: CreateProcessNotifyRoutine: %p\n", CreateInfo);
#endif

    if (CreateInfo) {
        UNICODE_STRING wszScanEventName;
        RtlInitUnicodeString(&wszScanEventName, L"\\BaseNamedObjects\\Global\\WindhawkScanForProcesses");

        OBJECT_ATTRIBUTES oaScan;
        RtlZeroMemory(&oaScan, sizeof(oaScan));
        InitializeObjectAttributes(&oaScan, &wszScanEventName, 0, NULL, NULL);

        HANDLE hScanEvent = NULL;
        rv = ZwOpenEvent(&hScanEvent, EVENT_MODIFY_STATE, &oaScan);
#ifdef WITH_DBGPRINT
        DbgPrint("WhSignalDrv: ZwOpenEvent -> %d\n", rv);
#endif

#ifdef WITH_WAIT_FOR_CONFIRMATION
        UNICODE_STRING wszScanDoneEventName;
        RtlInitUnicodeString(&wszScanDoneEventName, L"\\BaseNamedObjects\\Global\\WindhawkScanForProcessesDone");

        OBJECT_ATTRIBUTES oaScanDone;
        RtlZeroMemory(&oaScanDone, sizeof(oaScanDone));
        InitializeObjectAttributes(&oaScanDone, &wszScanDoneEventName, 0, NULL, NULL);

        HANDLE hScanDoneEvent = NULL;
        rv = ZwOpenEvent(&hScanDoneEvent, EVENT_MODIFY_STATE, &oaScanDone);
#ifdef WITH_DBGPRINT
        DbgPrint("WhSignalDrv: ZwOpenEvent -> %d\n", rv);
#endif
#endif
        if (hScanEvent && hScanEvent != INVALID_HANDLE_VALUE
#ifdef WITH_WAIT_FOR_CONFIRMATION
            && hScanDoneEvent && hScanDoneEvent != INVALID_HANDLE_VALUE
#endif
            ) {
            rv = ZwSetEvent(hScanEvent, NULL);
#ifdef WITH_DBGPRINT
            DbgPrint("WhSignalDrv: ZwSetEvent -> %d\n", rv);
#endif
            ZwClose(hScanEvent);
#ifdef WITH_WAIT_FOR_CONFIRMATION
            UINT64 i = -10000 * dwTimeoutMs;
            rv = ZwWaitForSingleObject(hScanDoneEvent, FALSE, (PLARGE_INTEGER)&i);
#ifdef WITH_DBGPRINT
            DbgPrint("WhSignalDrv: ZwWaitForSingleObject -> %d\n", rv);
#endif
            if (rv == STATUS_SUCCESS) {
                dwTimeoutMs = dwDefaultTimeoutMs;
            }
            else if (rv == STATUS_TIMEOUT) {
                dwTimeoutMs = 0;
            }
            ZwClose(hScanDoneEvent);
#endif
        }
    }
}

NTSTATUS DriverUnload(_In_ PDRIVER_OBJECT driverObject) {
    UNREFERENCED_PARAMETER(driverObject);
    if (bRegisteredRoutine) PsSetCreateProcessNotifyRoutineEx(&CreateProcessNotifyRoutine, TRUE);

#ifdef WITH_DBGPRINT
    DbgPrint("WhSignalDrv: DriverUnload\n");
#endif
    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT driverObject, _In_ PUNICODE_STRING registryPath) {
    UNREFERENCED_PARAMETER(registryPath);
    NTSTATUS rv = STATUS_SUCCESS;
#ifdef WITH_DBGPRINT
    DbgPrint("WhSignalDrv: DriverEntry\n");
#endif

    driverObject->DriverUnload = DriverUnload;

    rv = PsSetCreateProcessNotifyRoutineEx(&CreateProcessNotifyRoutine, FALSE);
    if (NT_SUCCESS(rv)) bRegisteredRoutine = TRUE;
#ifdef WITH_DBGPRINT
    DbgPrint("WhSignalDrv: PsSetCreateProcessNotifyRoutineEx -> %d\n", rv);
#endif

    return rv;
}