/*******************************************************************************
*
*  (C) COPYRIGHT Fyyre & EP_X0FF, 2010 - 2017
*
*  TITLE:       WHITELIST.C
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
#include "global.h"

//#define LOCK_DATA(x) EnterCriticalSection(x)
//#define UNLOCK_DATA(x) LeaveCriticalSection(x)

/*
* KdpRemoveEntry
*
* Purpose:
*
* Removes specific entry from the whitelist.
*
*/
VOID KdpRemoveEntry(
    _In_ PKDRVENTRY Entry
)
{
    if (!ARGUMENT_PRESENT(Entry))
        return;

    //
    // Note: lock is not required as this code always called by the same thread.
    //
    //LOCK_DATA(&KnownDriversListLock);
    RemoveEntryList(&Entry->ListEntry);
    //UNLOCK_DATA(&KnownDriversListLock);
    supHeapFree(Entry);
}

/*
* KdpFreeList
*
* Purpose:
*
* Disposes list of known drivers (whitelisted).
*
*/
VOID KdpFreeList(
    _In_ PLIST_ENTRY FreeList
)
{
    PKDRVENTRY KdEntry;

    //
    // Note: lock is not required as this code always called by the same thread.
    //
    //LOCK_DATA(&KnownDriversListLock);

    while (!IsListEmpty(FreeList)) {
        KdEntry = CONTAINING_RECORD(FreeList->Flink, KDRVENTRY, ListEntry);
        RemoveEntryList(FreeList->Flink);
        if (KdEntry != NULL) {
            supHeapFree(KdEntry);
        }
    }

    //UNLOCK_DATA(&KnownDriversListLock);
}

/*
* KdpFindEntry
*
* Purpose:
*
* Find corresponding entry in whitelist by given DriverName, hash or Tag.
*
*/
PKDRVENTRY KdpFindEntry(
    _In_opt_ ULONG_PTR Tag,
    _In_opt_ PWSTR DriverName,
    _In_reads_bytes_opt_(HashLength) PUCHAR Hash,
    _In_opt_ ULONG HashLength
)
{
    PLIST_ENTRY ListEntry;
    PKDRVENTRY tempEntry;
    PKDRVENTRY Entry = NULL;

    //
    // Note: lock is not required as this code always called by the same thread.
    //
    //LOCK_DATA(&KnownDriversListLock);

    ListEntry = KnownDriversListHead.Flink;

    while ((ListEntry != NULL) && (ListEntry != &KnownDriversListHead)) {

        tempEntry = CONTAINING_RECORD(ListEntry, KDRVENTRY, ListEntry);
        if (tempEntry != NULL) {
            //
            // Lookup by Tag.
            //
            if ((Tag != 0) && (tempEntry->Tag == Tag)) {
                Entry = tempEntry;
                break;
            }

            //
            // Lookup by driver name.
            //
            if (DriverName)
                if (_strcmpi_w(tempEntry->Packet.DriverName, DriverName) == 0) {
                    Entry = tempEntry;
                    break;
                }

            //
            // Lookup by hash.
            //
            if ((Hash) && (HashLength))
                if (RtlCompareMemory(tempEntry->Packet.HashValue, Hash, (SIZE_T)HashLength) == HashLength) {
                    Entry = tempEntry;
                    break;
                }
        }
        ListEntry = ListEntry->Flink;
    }

    //UNLOCK_DATA(&KnownDriversListLock);

    return Entry;
}

/*
* KdpAddEntry
*
* Purpose:
*
* Adds entry described by Driver name, hash + optionaly Tag.
*
*/
PKDRVENTRY KdpAddEntry(
    _In_opt_ ULONG_PTR Tag,
    _In_ ULONG_PTR Flags,
    _In_reads_bytes_(DriverNameLength) LPWSTR DriverName,
    _In_ SIZE_T DriverNameLength,
    _In_reads_bytes_(HashLength) PUCHAR Hash,
    _In_ ULONG HashLength,
    _In_opt_ PULONG State
)
{
    PKDRVENTRY Entry;

    if ((DriverNameLength == 0) ||
        (DriverNameLength > (MAX_PATH_DRV * sizeof(WCHAR))))
    {
        if (State)
            *State = ERROR_BAD_ARGUMENTS;
        return NULL;
    }

    if (HashLength > SHA256_DIGEST_LENGTH) {
        if (State)
            *State = ERROR_INVALID_PARAMETER;
        return NULL;
    }

    //
    // Check if entry already in list.
    //
    Entry = KdpFindEntry(0, NULL, Hash, HashLength);
    if (Entry != NULL) {
        if (State)
            *State = ERROR_ALREADY_EXISTS;
        return NULL;
    }

    //
    // Allocate memory for list item.
    //
    Entry = (PKDRVENTRY)supHeapAlloc(sizeof(KDRVENTRY));
    if (Entry == NULL) {
        if (State)
            *State = ERROR_NOT_ENOUGH_MEMORY;
        return NULL;
    }

    //
    // Copy data to list item.
    //
    Entry->Tag = Tag;
    Entry->Flags = Flags;

    RtlCopyMemory(Entry->Packet.HashValue, Hash, HashLength);

    _strncpy_w(
        Entry->Packet.DriverName,
        MAX_PATH_DRV,
        DriverName,
        DriverNameLength / sizeof(WCHAR));

    //
    // Insert entry to linked list.
    // Note: lock is not required as this code always called by the same thread.
    //
    //LOCK_DATA(&KnownDriversListLock);

    InsertTailList(&KnownDriversListHead, &Entry->ListEntry);

    //UNLOCK_DATA(&KnownDriversListLock);

    if (State)
        *State = ERROR_SUCCESS;

    return Entry;
}

/*
* KdpRemoveByName
*
* Purpose:
*
* Removes driver from whitelist by given driver name.
*
*/
BOOLEAN KdpRemoveByName(
    _In_ LPWSTR Driver
)
{
    PKDRVENTRY Entry;

    Entry = KdpFindEntry(0, Driver, NULL, 0);
    if (!Entry)
        return FALSE;

    KdpRemoveEntry(Entry);
    return TRUE;
}

/*
* KdpRemoveByTag
*
* Purpose:
*
* Removes driver from whitelist by given tag.
*
*/
BOOLEAN KdpRemoveByTag(
    _In_ ULONG_PTR Tag
)
{
    PKDRVENTRY Entry;

    Entry = KdpFindEntry(Tag, NULL, NULL, (ULONG)0);
    if (!Entry)
        return FALSE;

    KdpRemoveEntry(Entry);
    return TRUE;
}

/*
* KdpRemoveByHash
*
* Purpose:
*
* Removes driver from whitelist by given hash.
*
*/
BOOLEAN KdpRemoveByHash(
    _In_reads_bytes_(HashLength) PUCHAR Hash,
    _In_ ULONG HashLength
)
{
    PKDRVENTRY Entry;

    if (HashLength > SHA256_DIGEST_LENGTH)
        return FALSE;

    Entry = KdpFindEntry(0, NULL, Hash, HashLength);
    if (!Entry)
        return FALSE;

    KdpRemoveEntry(Entry);
    return TRUE;
}

/*
* KnownDriversCreate
*
* Purpose:
*
* Initialize known drivers list global variables.
*
*/
VOID KnownDriversCreate(
    VOID
)
{
    InitializeListHead(&KnownDriversListHead);
    //InitializeCriticalSection(&KnownDriversListLock);
}

/*
* KnownDriversDestroy
*
* Purpose:
*
* Shutdown routine for whitelist support mechanism.
* Called at whitelist dispose.
*
*/
VOID KnownDriversDestroy(
    VOID
)
{
    KdpFreeList(&KnownDriversListHead);
}

/*
* KnownDriversAddEntry
*
* Purpose:
*
* Add driver to whitelist.
*
*/
PKDRVENTRY KnownDriversAddEntry(
    _In_opt_ ULONG_PTR Tag,
    _In_ ULONG_PTR Flags,
    _In_reads_bytes_(DriverNameLength) LPWSTR DriverName,
    _In_ SIZE_T DriverNameLength, //Length in bytes
    _In_reads_bytes_(HashLength) PUCHAR Hash,
    _In_ ULONG HashLength,
    _In_opt_ PULONG State)
{
    PKDRVENTRY Entry;

    Entry = KdpAddEntry(Tag, Flags, DriverName, DriverNameLength, Hash, HashLength, State);

    return (Entry);
}

/*
* KnownDriversRemoveEntry
*
* Purpose:
*
* Remove driver to whitelist.
*
*/
BOOLEAN KnownDriversRemoveEntry(
    _In_ ULONG_PTR RemovalType,
    _In_ PKDRVPACKET Packet)
{
    switch (RemovalType) {

    case DELETE_BY_NAME:
        return KdpRemoveByName(Packet->DriverName);
        break;

    case DELETE_BY_HASH:
        return KdpRemoveByHash(Packet->HashValue, sizeof(Packet->HashValue));
        break;

    default:
        return KdpRemoveByTag(RemovalType);
        break;
    }
}

/*
* KnownDriversEnumList
*
* Purpose:
*
* Enumerate all entries in whitelist and callback for each.
*
*/
DWORD KnownDriversEnumList(
    _In_ KDENUMCALLBACK EnumCallback,
    _In_opt_ PVOID UserContext
)
{
    BOOLEAN StopEnumeration = FALSE;
    PLIST_ENTRY ListEntry;
    PKDRVENTRY KdEntry;

    if (EnumCallback == NULL)
        return ERROR_INVALID_PARAMETER;

    //
    // Note: lock is not required as this code always called by the same thread.
    //
    //LOCK_DATA(&KnownDriversListLock);

    ListEntry = KnownDriversListHead.Flink;

    while (ListEntry != &KnownDriversListHead) {
        KdEntry = CONTAINING_RECORD(ListEntry, KDRVENTRY, ListEntry);
        if (KdEntry) {
            EnumCallback(UserContext, KdEntry, &StopEnumeration);
        }
        if (StopEnumeration)
            break;
        ListEntry = ListEntry->Flink;
    }

    //UNLOCK_DATA(&KnownDriversListLock);
    return ERROR_SUCCESS;
}


/*
* KdpNotifyDriverCallback
*
* Purpose:
*
* Callback to send whitelist entry to driver.
*
*/
VOID KdpNotifyDriverCallback(
    _In_opt_ PVOID Context,
    _In_ PKDRVENTRY Entry,
    _Inout_ PBOOLEAN StopEnumeration
)
{
    SIZE_T Length;

    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(StopEnumeration);

    Length = _strlen(Entry->Packet.DriverName) * sizeof(WCHAR);
    if (Length) {

        DmManageWhiteList(TRUE,
            Entry->Tag,
            Entry->Flags,
            Entry->Packet.DriverName,
            Length,
            Entry->Packet.HashValue,
            sizeof(Entry->Packet.HashValue));

    }
}

/*
* KnownDriversInformDriver
*
* Purpose:
*
* Copy whitelist to driver.
*
*/
VOID KnownDriversInformDriver(
    VOID
)
{
    KnownDriversEnumList(KdpNotifyDriverCallback, NULL);
}
