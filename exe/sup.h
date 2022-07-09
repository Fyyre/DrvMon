/*******************************************************************************
*
*  (C) COPYRIGHT Fyyre & EP_X0FF, 2010 - 2017
*
*  TITLE:       SUP.H
*
*  VERSION:     3.00
*
*  DATE:        10 Apr 2017
*
*  Common header file for the program support routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

typedef union {
    WCHAR Name[sizeof(ULARGE_INTEGER) / sizeof(WCHAR)];
    ULARGE_INTEGER Alignment;
} ALIGNEDNAME;

typedef HWND(WINAPI *pfnHtmlHelpW)(
    _In_opt_ HWND hwndCaller,
    _In_ LPCWSTR pszFile,
    _In_ UINT uCommand,
    _In_ DWORD_PTR dwData
    );

typedef BOOLEAN(CALLBACK *HASHCALLBACK)(
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _Out_writes_bytes_(HashLength) PVOID Hash,
    _In_ ULONG HashLength);

PVOID supHeapAlloc(
    _In_ SIZE_T Size);

BOOL supHeapFree(
    _In_ PVOID Memory);

PBYTE supLdrQueryResourceData(
    _In_ ULONG_PTR ResourceId,
    _In_ PVOID DllHandle,
    _In_ PULONG DataSize);

PBYTE supReadFileToBuffer(
    _In_ LPWSTR lpFileName,
    _Inout_opt_ LPDWORD lpBufferSize);

VOID supSetWaitCursor(
    _In_ BOOL fSet);

VOID supSetMenuIcon(
    _In_ HMENU hMenu,
    _In_ UINT Item,
    _In_ ULONG_PTR IconData);

VOID supCenterWindow(
    _In_ HWND hwnd);

BOOL supOpenDialogExecute(
    _In_ HWND OwnerWindow,
    _Inout_ LPWSTR OpenFileName,
    _In_ LPWSTR lpDialogFilter);

BOOL supSaveDialogExecute(
    _In_ HWND OwnerWindow,
    _Inout_ LPWSTR SaveFileName,
    _In_ LPWSTR lpDialogFilter,
    _In_opt_ LPWSTR lpstrDefExt);

BOOL supSelectDirectory(
    _In_ HWND hwnd,
    _In_ LPWSTR lpCaption,
    _Inout_ LPWSTR lpDirectory,
    _In_ SIZE_T cchDirectory);

VOID supCreateToolbarButtons(
    _In_ HWND hWndToolbar,
    _In_ HIMAGELIST hImageList);

UINT supIsNtNamePrefix(
    _In_ LPWSTR lpName,
    _In_ SIZE_T cbName);

VOID supShowHelp(
    VOID);

BOOL supConvertFileName(
    _In_ LPWSTR NtFileName,
    _In_ SIZE_T ccNtFileName,
    _In_ LPWSTR DosFileName,
    _In_ SIZE_T ccDosFileName);

BOOL DmSetOutputDirectory(
    _In_ UNICODE_STRING *usOutputDirectory);

BOOL DmSetInternalFlags(
    _In_ ULONG Flags);

BOOL DmManageWhiteList(
    _In_ BOOLEAN AddEntry,
    _In_ ULONG_PTR Tag,
    _In_ ULONG_PTR Flags,
    _In_reads_bytes_opt_(DriverNameLength) LPWSTR DriverName,
    _In_opt_ SIZE_T DriverNameLength,
    _In_reads_bytes_(HashLength) PUCHAR Hash,
    _In_ ULONG HashLength);

_Success_(return == TRUE)
BOOLEAN supPrintHash(
    _In_reads_bytes_(HashLength) PUCHAR Hash,
    _In_ ULONG HashLength,
    _Out_writes_bytes_(OutputLength) PUCHAR Output,
    _In_ ULONG OutputLength,
    _In_ BOOLEAN LowerCase);

LPWSTR supPrintHashEx(
    _In_reads_bytes_(Length) PUCHAR Buffer,
    _In_ ULONG Length,
    _In_ BOOLEAN LowerCase);

BOOLEAN supSha256Buffer(
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _Out_writes_bytes_(HashLength) PVOID Hash,
    _In_ ULONG HashLength);

_Success_(return == TRUE)
BOOLEAN supHashFile(
    _In_ LPWSTR lpFileName,
    _Out_writes_bytes_(HashLength) PVOID Hash,
    _In_ ULONG HashLength,
    _In_ HASHCALLBACK HashCallback);

DWORD supExtractDriver(
    _In_ LPCWSTR lpExtractTo);

HANDLE supOpenDrvMon(
    _In_ LPWSTR lpDriverDevice,
    _Out_opt_ NTSTATUS *OutStatus);

BOOLEAN supJumpToFile(
    _In_ LPWSTR lpFilePath);

VOID supShellExecuteVerb(
    _In_ HWND hwnd,
    _In_ LPWSTR lpFilePath,
    _In_opt_ LPWSTR lpDirectory,
    _In_ LPWSTR lpVerb);

BOOL supRunSearchQueryGoogle(
    _In_ HWND hwnd,
    _In_reads_bytes_(LookupValueLength) LPWSTR LookupValue,
    _In_ SIZE_T LookupValueLength);

BOOL supReadWhiteList(
    _In_ HKEY RootKey);

VOID supWriteWhiteList(
    _In_ HKEY RootKey);

VOID supWhiteListLegacyAddVgaEntry(
    VOID);

VOID supxxxTestHash(
    VOID);

VOID supxxxTestFileExists(
    VOID);

VOID supxxxTestKD(
    VOID);
