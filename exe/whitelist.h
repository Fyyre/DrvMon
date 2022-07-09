/*******************************************************************************
*
*  (C) COPYRIGHT Fyyre & EP_X0FF, 2010 - 2017
*
*  TITLE:       WHITELIST.H
*
*  VERSION:     3.00
*
*  DATE:        10 Apr 2017
*
*  Header file for DrvMon whitelist routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

//
// Synchronization mutex and list entry head.
//
LIST_ENTRY KnownDriversListHead;
//CRITICAL_SECTION KnownDriversListLock;

//constants for deleting from whitelist 
#define DELETE_BY_TAG  0
#define DELETE_BY_NAME 1
#define DELETE_BY_HASH 2

//DRVMON PACKET FLAGS
#define PACKET_FLAGS_DRIVER_WHITELISTED 2

//
// Whitelist entry flags
//
#define ENTRY_FLAGS_DEFAULT         0
#define ENTRY_FLAGS_SILENTAPPROVE   1

//
//  Known drivers structures.
//
#pragma pack(push, 1)
typedef struct _KDRVPACKET {
    UCHAR HashValue[SHA256_DIGEST_LENGTH];
    WCHAR DriverName[MAX_PATH_DRV];
} KDRVPACKET, *PKDRVPACKET;

//
//  DrvMon whitelist entry.
//  Tag 1, 2 values are reserved!
typedef struct _KDRVENTRY {
    LIST_ENTRY ListEntry;
    ULONG_PTR Tag;
    ULONG_PTR Flags;
    KDRVPACKET Packet;
} KDRVENTRY, *PKDRVENTRY;
#pragma pack(pop)

// 
// Public routines.
//

typedef VOID(CALLBACK *KDENUMCALLBACK)(
    _In_opt_ PVOID Context,
    _In_ PKDRVENTRY Entry,
    _Inout_ PBOOLEAN StopEnumeration);

VOID KnownDriversCreate(
    VOID);

VOID KnownDriversDestroy(
    VOID);

PKDRVENTRY KnownDriversAddEntry(
    _In_opt_ ULONG_PTR Tag,
    _In_ ULONG_PTR Flags,
    _In_reads_bytes_(DriverNameLength) LPWSTR DriverName,
    _In_ SIZE_T DriverNameLength,
    _In_reads_bytes_(HashLength) PUCHAR Hash,
    _In_ ULONG HashLength,
    _In_opt_ PULONG State);

BOOLEAN KnownDriversRemoveEntry(
    _In_ ULONG_PTR RemovalType,
    _In_ PKDRVPACKET Packet);

DWORD KnownDriversEnumList(
    _In_ KDENUMCALLBACK EnumCallback,
    _In_opt_ PVOID UserContext);

VOID KnownDriversInformDriver(
    VOID);
