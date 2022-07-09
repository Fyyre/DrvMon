#if !defined UNICODE
#error ANSI build is not supported
#endif

#if (_MSC_VER >= 1900) 
#ifdef _DEBUG
#pragma comment(lib, "vcruntimed.lib")
#pragma comment(lib, "ucrtd.lib")
#else
#pragma comment(lib, "libvcruntime.lib")
#endif
#endif

//
// Ignored warnings
//
#pragma warning(disable: 4005) // macro redefinition
#pragma warning(disable: 4201) // nonstandard extension used : nameless struct/union
#pragma warning(disable: 6102) // Using %s from failed function call at line %u
#pragma warning(disable: 6320) // Exception-filter expression is the constant EXCEPTION_EXECUTE_HANDLER
#if (_MSC_VER >= 1900)
#pragma warning(disable: 4091) // 'typedef ': ignored on left of '' when no variable is declared
#pragma warning(disable: 4311) // 'type cast': pointer truncation from %s to %s
#pragma warning(disable: 4312) // 'type cast': conversion from %s to %s of greater size
#endif

#include <Windows.h>
#include "..\..\..\shared\minirtl\minirtl.h"
#include "..\..\..\shared\ntos.h"
#include <ntstatus.h>

#define DUMMYDRVREG L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\DummyDrv"

NTSTATUS NativeAdjustPrivileges(
    _In_ ULONG Privilege
)
{
    NTSTATUS Status;
    HANDLE TokenHandle;

    LUID Luid;
    TOKEN_PRIVILEGES TokenPrivileges;

    Luid.LowPart = Privilege;
    Luid.HighPart = 0;

    TokenPrivileges.PrivilegeCount = 1;
    TokenPrivileges.Privileges[0].Luid = Luid;
    TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    Status = NtOpenProcessToken(
        NtCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        &TokenHandle);

    if (NT_SUCCESS(Status)) {
        Status = NtAdjustPrivilegesToken(
            TokenHandle,
            FALSE,
            &TokenPrivileges,
            sizeof(TOKEN_PRIVILEGES),
            (PTOKEN_PRIVILEGES)NULL,
            NULL);

        NtClose(TokenHandle);
    }

    if (Status == STATUS_NOT_ALL_ASSIGNED)
        Status = STATUS_PRIVILEGE_NOT_HELD;

    return Status;
}

NTSTATUS NativeLoadDriver(
    _In_ PWSTR DrvFullPath,
    _In_ PWSTR KeyName,
    _In_opt_ PWSTR DisplayName,
    _In_ BOOL ReloadDrv
)
{
    UNICODE_STRING ValueName, drvName;
    OBJECT_ATTRIBUTES attr;

    HANDLE hDrvKey;
    ULONG data, dataSize = 0;
    NTSTATUS ns = STATUS_UNSUCCESSFUL;
    hDrvKey = NULL;

    __try
    {
        if (!ARGUMENT_PRESENT(KeyName)) {
            ns = STATUS_OBJECT_NAME_NOT_FOUND;
            __leave;
        }

        RtlInitUnicodeString(&drvName, KeyName);
        InitializeObjectAttributes(&attr, &drvName, OBJ_CASE_INSENSITIVE, 0, NULL);
        ns = NtCreateKey(&hDrvKey, KEY_ALL_ACCESS, &attr, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
        if (!NT_SUCCESS(ns)) {
            __leave;
        }

        if (ARGUMENT_PRESENT(DrvFullPath)) {
            RtlInitUnicodeString(&ValueName, L"ImagePath");
            dataSize = (ULONG)(1 + _strlen(DrvFullPath)) * sizeof(WCHAR);
            ns = NtSetValueKey(hDrvKey, &ValueName, 0, REG_EXPAND_SZ, (PVOID)DrvFullPath, dataSize);
            if (!NT_SUCCESS(ns)) {
                __leave;
            }
        }

        data = 1;
        RtlInitUnicodeString(&ValueName, L"Type");
        ns = NtSetValueKey(hDrvKey, &ValueName, 0, REG_DWORD, (PVOID)&data, sizeof(DWORD));
        if (!NT_SUCCESS(ns)) {
            __leave;
        }

        data = 3;
        RtlInitUnicodeString(&ValueName, L"Start");
        ns = NtSetValueKey(hDrvKey, &ValueName, 0, REG_DWORD, (PVOID)&data, sizeof(DWORD));
        if (!NT_SUCCESS(ns)) {
            __leave;
        }

        data = SERVICE_ERROR_NORMAL;
        RtlInitUnicodeString(&ValueName, L"ErrorControl");
        ns = NtSetValueKey(hDrvKey, &ValueName, 0, REG_DWORD, (PVOID)&data, sizeof(DWORD));
        if (!NT_SUCCESS(ns)) {
            __leave;
        }

        if (ARGUMENT_PRESENT(DisplayName)) {
            RtlInitUnicodeString(&ValueName, L"DisplayName");
            dataSize = (ULONG)(1 + _strlen(DisplayName)) * sizeof(WCHAR);
            ns = NtSetValueKey(hDrvKey, &ValueName, 0, REG_SZ, DisplayName, dataSize);
            if (!NT_SUCCESS(ns)) {
                __leave;
            }
        }
        NtClose(hDrvKey);
        hDrvKey = NULL;

        ns = NtLoadDriver(&drvName);
        if (ns == STATUS_IMAGE_ALREADY_LOADED) {
            if (ReloadDrv == TRUE) {
                NtUnloadDriver(&drvName); //unload previous driver version
                NtYieldExecution();
                ns = NtLoadDriver(&drvName);
            }
            else {
                ns = STATUS_SUCCESS;
            }
        }

    }
    __finally {
        if (hDrvKey != NULL) {
            NtClose(hDrvKey);
        }
    }
    return ns;
}

void main() 
{
    NTSTATUS Status;

    HANDLE Link = NULL;

    UNICODE_STRING str, drvname;
    OBJECT_ATTRIBUTES Obja;

    WCHAR szBuffer[MAX_PATH + 1];

    OutputDebugString(L"[DrvMonTest] Loader Started\n");

    if (!NT_SUCCESS(NativeAdjustPrivileges(SE_LOAD_DRIVER_PRIVILEGE)))
        return;

    _strcpy(szBuffer, L"\\??\\");
    _strcat(szBuffer, NtCurrentPeb()->ProcessParameters->CurrentDirectory.DosPath.Buffer);
    _strcat(szBuffer, L"dummy.sys");

    RtlInitUnicodeString(&str, L"\\*");
    RtlInitUnicodeString(&drvname, szBuffer);
    InitializeObjectAttributes(&Obja, &str, OBJ_CASE_INSENSITIVE, 0, NULL);

    Status = NtCreateSymbolicLinkObject(&Link, SYMBOLIC_LINK_ALL_ACCESS, &Obja, &drvname);

    RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
    _strcpy(szBuffer, L"[DrvMonTest] NtCreateSymbolicLinkObject result = 0x");
    ultohex(Status, _strend(szBuffer));
    OutputDebugString(szBuffer);

    OutputDebugString(L"[DrvMonTest] Symlink set\n");
    Status = NativeLoadDriver(L"\\*", DUMMYDRVREG, NULL, TRUE);

    RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
    _strcpy(szBuffer, L"[DrvMonTest] NativeLoadDriver result = 0x");
    ultohex(Status, _strend(szBuffer));
    OutputDebugString(szBuffer);

    if (Link) NtClose(Link);
}
