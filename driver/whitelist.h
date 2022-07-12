/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2010 - 2017
*
*  TITLE:       WHITELIST.H
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
// Synchronization mutex and list entry head.
//
LIST_ENTRY KnownDriversListHead;
KMUTEX KnownDriversListLock;

//
// Constants for deleting from whitelist
//
#define DELETE_BY_TAG  0
#define DELETE_BY_NAME 1
#define DELETE_BY_HASH 2

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
    WCHAR DriverName[MAX_PATH_DRV + 1];
} KDRVPACKET, *PKDRVPACKET;

// DrvMon whitelist entry.
// Tag 1, 2 values are reserved!
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
VOID KnownDriversCreate(
    VOID);

VOID KnownDriversDestroy(
    VOID);

BOOLEAN KnownDriversAddEntry(
    _In_opt_ ULONG_PTR Tag,
    _In_ ULONG_PTR Flags,
    _In_reads_bytes_(DriverNameLength) LPWSTR DriverName,
    _In_ SIZE_T DriverNameLength,
    _In_reads_bytes_(HashLength) PUCHAR Hash,
    _In_ ULONG HashLength);

BOOLEAN KnownDriversRemoveEntry(
    _In_ ULONG_PTR RemovalType,
    _In_ PKDRVPACKET Packet);

PKDRVENTRY KnownDriverFindEntryByHash(
    _In_reads_bytes_opt_(HashLength) PUCHAR Hash,
    _In_opt_ ULONG HashLength);
