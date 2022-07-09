/*******************************************************************************
*
*  (C) COPYRIGHT hfiref0x & Fyyre, 2010 - 2017
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
#include "drvmon.h"

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

    LOCK_DATA(&KnownDriversListLock);

    RemoveEntryList(&Entry->ListEntry);
    mmfree(Entry);

    UNLOCK_DATA(&KnownDriversListLock);
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

    LOCK_DATA(&KnownDriversListLock);

#ifdef VERBOSE
    DbgPrint("[DM] KdpFreeList");
#endif

    while (!IsListEmpty(FreeList)) {
        KdEntry = CONTAINING_RECORD(FreeList->Flink, KDRVENTRY, ListEntry);
        RemoveEntryList(FreeList->Flink);
        if (KdEntry != NULL) {

#ifdef VERBOSE
            DbgPrint("[DM] KdpFreeList, releasing entry %p", KdEntry);
#endif
            mmfree(KdEntry);
        }
    }

    UNLOCK_DATA(&KnownDriversListLock);
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
    PLIST_ENTRY ListEntry;;
    PKDRVENTRY tempEntry;
    PKDRVENTRY Entry = NULL;

    LOCK_DATA(&KnownDriversListLock);

    ListEntry = KnownDriversListHead.Flink;

#ifdef VERBOSE
    DbgPrint("KdpFindEntry, ListEntry = %p", ListEntry);
#endif

    while (ListEntry != &KnownDriversListHead) {

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
            if ((Hash != NULL) && (HashLength != 0))
                if (RtlCompareMemory(tempEntry->Packet.HashValue, Hash, HashLength) == HashLength) {
                    Entry = tempEntry;
                    break;
                }
        }
        ListEntry = ListEntry->Flink;
    }

    UNLOCK_DATA(&KnownDriversListLock);

#ifdef VERBOSE
    if (Entry != NULL)
        DbgPrint("[DM] KdpFindEntry, entry found %p", Entry);
#endif

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
    _In_ ULONG HashLength   
)
{
    PKDRVENTRY Entry;

    if ((DriverNameLength == 0) ||
        (DriverNameLength > (MAX_PATH_DRV * sizeof(WCHAR))))
    {
        return NULL;
    }

    if (HashLength > SHA256_DIGEST_LENGTH)
        return NULL;
 
    //
    // Check if entry already in list.
    //
    Entry = KdpFindEntry(0, NULL, Hash, HashLength);
    if (Entry != NULL) {
        return NULL;
    }

    //
    // Allocate memory for list item.
    //
    Entry = (PKDRVENTRY)mmalloc(
        NonPagedPool,
        sizeof(KDRVENTRY));

    if (Entry == NULL)
        return NULL;

    RtlSecureZeroMemory(Entry, sizeof(KDRVENTRY));
    
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

#ifdef VERBOSE
    DbgPrint("[DM] Entry->Packet.DriverName %wS", Entry->Packet.DriverName);
#endif

    //
    // Insert entry to linked list.
    //
    LOCK_DATA(&KnownDriversListLock);
    
    InsertTailList(&KnownDriversListHead, &Entry->ListEntry);
    
    UNLOCK_DATA(&KnownDriversListLock);

#ifdef VERBOSE
    DbgPrint("[DM] KdpAddEntry, entry set %p", Entry);
#endif

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

    Entry = KdpFindEntry(Tag, NULL, NULL, 0);
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
    KeInitializeMutex(&KnownDriversListLock, 0);
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
    LARGE_INTEGER waitLi;

    KdpFreeList(&KnownDriversListHead);

    waitLi.QuadPart = RELATIVE_TIME(SECONDS(1));
    KeDelayExecutionThread(KernelMode, FALSE, &waitLi);
}

/*
* KnownDriversAddEntry
*
* Purpose:
*
* Add driver to whitelist.
*
*/
BOOLEAN KnownDriversAddEntry(
    _In_opt_ ULONG_PTR Tag,
    _In_ ULONG_PTR Flags,
    _In_reads_bytes_(DriverNameLength) LPWSTR DriverName,
    _In_ SIZE_T DriverNameLength,
    _In_reads_bytes_(HashLength) PUCHAR Hash,
    _In_ ULONG HashLength
    )
{
    PKDRVENTRY Entry;

    Entry = KdpAddEntry(Tag, Flags, DriverName, DriverNameLength, Hash, HashLength);

    return (Entry != NULL);
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
* KnownDriverFindEntryByHash
*
* Purpose:
*
* Find entry by hash.
*
*/
PKDRVENTRY KnownDriverFindEntryByHash(
    _In_reads_bytes_opt_(HashLength) PUCHAR Hash,
    _In_opt_ ULONG HashLength
)
{
    return KdpFindEntry(0, NULL, Hash, HashLength);
}