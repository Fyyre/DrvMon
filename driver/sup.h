/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2010 - 2017
*
*  TITLE:       SUP.H
*
*  VERSION:     3.00
*
*  DATE:        10 Apr 2017
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

//
// Misc routines and definitions.
//
typedef union {
    WCHAR Name[sizeof(ULARGE_INTEGER) / sizeof(WCHAR)];
    ULARGE_INTEGER Alignment;
} ALIGNEDNAME;

ULONG_PTR align(
    ULONG_PTR x,
    ULONG_PTR base);

wchar_t *supJustFileName(
    const wchar_t *f);

USHORT supIsNtNamePrefix(
    _In_ LPWSTR lpName,
    _In_ SIZE_T cbName);

//
// Security routines.
//

NTSTATUS supSetDefaultSecurity(
    _In_ HANDLE hObject);

//
// Mdl routines and definitions.
//
typedef struct _MAPPED_MDL {
    PMDL Mdl;
    PVOID Address;
} MAPPED_MDL, *PMAPPED_MDL;

NTSTATUS supCreateMappedMdl(
    _In_ PVOID Address,
    _In_ ULONG Length,
    _Out_ MAPPED_MDL *MappedMdl,
    _In_ BOOLEAN  IsKernelMode);

VOID supFreeMappedMdl(
    _In_ MAPPED_MDL *MappedMdl,
    _In_ BOOLEAN IsKernelMode);

//
// File I/O routines.
//

BOOLEAN supGetFileSize(
    _In_ HANDLE hFile,
    _Inout_opt_ PULONG pLowPart,
    _Inout_opt_ PULONG pHighPart);

BOOLEAN supCopyFile(
    _In_ PUNICODE_STRING DstFile,
    _In_ PUNICODE_STRING SrcFile);

BOOLEAN supFileExists(
    _In_ PUNICODE_STRING FileName);

BOOLEAN supIsSymbolicLink(
    _In_ PUNICODE_STRING FileName);

BOOLEAN supGetFileImageName(
    _In_ PUNICODE_STRING InputImageName,
    _Inout_ PUNICODE_STRING OutputImageName);


//
// Hash routines and definitions. 
// 
typedef struct DM_HASH_CONTEXT {
    ULONG Total[2];
    ULONG State[8];
    UCHAR Buffer[64];
} DM_HASH_CONTEXT, *PDM_HASH_CONTEXT;


typedef BOOLEAN(NTAPI *HASHCALLBACK)(
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _Out_writes_bytes_(HashLength) PVOID Hash,
    _In_ ULONG HashLength);

VOID supInitializeHash(
    _Out_ PDM_HASH_CONTEXT Context);

VOID supUpdateHash(
    _Inout_ PDM_HASH_CONTEXT Context,
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length);

BOOLEAN supFinalHash(
    _Inout_ PDM_HASH_CONTEXT Context,
    _Out_writes_bytes_(HashLength) PVOID Hash,
    _In_ ULONG HashLength);

BOOLEAN supSha256Buffer(
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _Out_writes_bytes_(HashLength) PVOID Hash,
    _In_ ULONG HashLength);

_Success_(return == TRUE)
BOOLEAN supHashFile(
    _In_ PUNICODE_STRING FileName,
    _Out_writes_bytes_(HashLength) PVOID Hash,
    _In_ ULONG HashLength,
    _In_ HASHCALLBACK HashCallback);

_Success_(return == TRUE)
BOOLEAN supPrintHash(
    _In_reads_bytes_(HashLength) PUCHAR Hash,
    _In_ ULONG HashLength,
    _Out_writes_bytes_(OutputLength) PUCHAR Output,
    _In_ ULONG OutputLength);
