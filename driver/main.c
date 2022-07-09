/*******************************************************************************
*
*  (C) COPYRIGHT hfiref0x & Fyyre, 2010 - 2017
*
*  TITLE:       MAIN.C
*
*  VERSION:     3.00
*
*  DATE:        10 Apr 2017
*
*  Codename: Sendai
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "drvmon.h"

static DRVMONCONTEXT dmctx;

const UCHAR DmPatchCodeMZ[] = { 0x4D, 0x5A, 0x52, 0x45, 0xB8, 0x01, 0x00, 0x00, 0xC0, 0xC3 };
const UCHAR DmPathCodeEP[] = { 0xB8, 0x01, 0x00, 0x00, 0xC0, 0xC3 };


/*
* DmWriteMemory
*
* Purpose:
*
* Write memory to given address.
*
*/
NTSTATUS DmWriteMemory(
    _In_ PVOID SrcAddress,
    _In_ PVOID DestAddress,
    _In_ ULONG Size,
    _In_ BOOLEAN Protect,
    _In_opt_ ULONG NewProtect,
    _Out_opt_ PULONG BytesWritten
)
{
    PMDL		mdl;
    NTSTATUS	status = STATUS_SUCCESS;

    PAGED_CODE();

    if (BytesWritten)
        *BytesWritten = 0;

    mdl = IoAllocateMdl(DestAddress, Size, FALSE, FALSE, NULL);
    if (mdl == NULL) {

#ifdef VERBOSE
        DbgPrint("[DM] DmWriteMemory: failed to create MDL at write.\n");
#endif

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    __try {

        if (DestAddress >= MmSystemRangeStart)
            if (!MmIsAddressValid(DestAddress)) {

#ifdef VERBOSE
                DbgPrint("[DM] DmWriteMemory: Invalid address.\n");
#endif

                return STATUS_ACCESS_VIOLATION;
            }

        MmProbeAndLockPages(mdl, KernelMode, IoWriteAccess);
        DestAddress = MmGetSystemAddressForMdlSafe(mdl, HighPagePriority);
        if (DestAddress != NULL) {

#ifdef VERBOSE
            DbgPrint("[DM] DmWriteMemory: mapped at %p for write.\n", DestAddress);
#endif

            if (Protect)
                status = MmProtectMdlSystemAddress(mdl, NewProtect);

            __movsb((PUCHAR)DestAddress, (const UCHAR *)SrcAddress, Size);
            MmUnmapLockedPages(DestAddress, mdl);
            MmUnlockPages(mdl);

            if (BytesWritten)
                *BytesWritten = Size;
        }
        else {
            status = STATUS_ACCESS_VIOLATION;

#ifdef VERBOSE
            DbgPrint("[DM] DmWriteMemory: MmGetSystemAddressForMdlSafe failed at write.\n");
#endif

        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = STATUS_ACCESS_VIOLATION;

#ifdef VERBOSE
        DbgPrint("[DM] DmWriteMemory: MmProbeAndLockPages failed at write.\n");
#endif

    }

    IoFreeMdl(mdl);
    return status;
}

/*
* DmpBlockDriver
*
* Purpose:
*
* Block driver loading by either MZ header patch or by Entry point overwrite.
*
*/
NTSTATUS DmpBlockDriver(
    _In_ PVOID ImageBase
)
{
    BOOLEAN Protect = FALSE;
    NTSTATUS Status;
    ULONG Size, BytesWritten = 0;
    PVOID Buffer;
    PIMAGE_NT_HEADERS64 NtHeaders;
    ULONG_PTR EntryPoint;

    PAGED_CODE();

    NtHeaders = RtlImageNtHeader(ImageBase);
    if (NtHeaders) {
        EntryPoint = NtHeaders->OptionalHeader.AddressOfEntryPoint;
        if (EntryPoint != 0) {
            EntryPoint = (ULONG_PTR)ImageBase + EntryPoint;
            Buffer = (PVOID)DmPathCodeEP;
            Size = sizeof(DmPathCodeEP);
        }
        else {
            EntryPoint = (ULONG_PTR)ImageBase;
            Buffer = (PVOID)DmPatchCodeMZ;
            Size = sizeof(DmPatchCodeMZ);
        }
        Status = DmWriteMemory(Buffer, (PVOID)EntryPoint, Size, Protect, 0, &BytesWritten);

#ifdef VERBOSE
        DbgPrint("[DM] Patch bytes %lu written %lu", Size, BytesWritten);
#endif

    }
    else {
        Status = STATUS_CORRUPT_SYSTEM_FILE;
    }
    return Status;
}

/*
* DmpDisallowCallback
*
* Purpose:
*
* Callback used after user mode interactions.
*
*/
NTSTATUS DmpDisallowCallback(
    _In_ PIMAGE_INFO ImageInfo,
    _In_reads_bytes_opt_(HashLength) PUCHAR Hash,
    _In_opt_ ULONG HashLength,
    _In_ BOOLEAN UseWhiteList,
    _Out_opt_ PBOOLEAN SilentApprove
)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    PKDRVENTRY DriverEntry = NULL;

    PAGED_CODE();

#ifdef VERBOSE
    DbgPrint("[DM] DmpDisallowCallback(ImageInfo = %p Hash = %p HashLength = %lu UseWhiteList = %lu)",
        ImageInfo,
        Hash,
        HashLength,
        UseWhiteList);
#endif

    if (SilentApprove)
        *SilentApprove = FALSE;

    //
    // If we can use whitelist, check driver in it first.
    //
    if (UseWhiteList) {

        if ((Hash != NULL) && (HashLength == SHA256_DIGEST_LENGTH)) {
            //
            // Lookup driver by hash.
            //
            DriverEntry = KnownDriverFindEntryByHash(Hash, HashLength);
            if (DriverEntry != NULL) {

                //
                // Set SilentApprove value.
                // If TRUE then DrvMon will NOT report back to usermode approve event.
                //
                if (SilentApprove)
                    *SilentApprove = ((DriverEntry->Flags & ENTRY_FLAGS_SILENTAPPROVE) > 0);

                //
                // Found in whitelist, allow driver.
                //
                return STATUS_VALID_IMAGE_HASH;
            }
        }
    }

    //
    // UseWhiteList not set to TRUE or entry not found in whitelist.
    // Block it.
    //   
    if (ImageInfo) {
        Status = DmpBlockDriver(ImageInfo->ImageBase);

#ifdef VERBOSE
        DbgPrint("[DM] DmpBlockDriver = %lx", Status);
#endif

    }

    return Status;
}

/*
* DmpLoadFilterCallback
*
* Purpose:
*
* Process callback data for user mode interaction.
*
*/
NTSTATUS DmpLoadFilterCallback(
    _In_ PWSTR ImageNameBuffer,
    _In_ PIMAGE_INFO  ImageInfo,
    _In_reads_bytes_opt_(HashLength) PUCHAR Hash,
    _In_opt_ ULONG HashLength
)
{
    NTSTATUS Status;
    MAPPED_MDL MappedMdl;
    PKDRVENTRY drvEntry = NULL;
    PDRVMON_PACKET Packet = NULL;
    ULONG UserAnswer = 0;
    //KLOCK_QUEUE_HANDLE LockHandle;
    BOOLEAN bDriverWhitelisted = FALSE;

    PAGED_CODE();

    if (PsGetCurrentProcess() != PsInitialSystemProcess)
        return STATUS_UNSUCCESSFUL;

    if (dmctx.SharedMemory == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    if ((Hash) && (HashLength)) {
        drvEntry = KnownDriverFindEntryByHash(Hash, HashLength);
        if (drvEntry != NULL) {
            bDriverWhitelisted = TRUE;

            //
            // Return from callback if driver is marked for silent approve.
            //
            if ((drvEntry->Flags & ENTRY_FLAGS_SILENTAPPROVE) > 0)
                return STATUS_VALID_IMAGE_HASH;
        }
    }

    Status = supCreateMappedMdl(dmctx.SharedMemory, SHARED_SPACE_SIZE, &MappedMdl, FALSE);
    if (NT_SUCCESS(Status)) {
        Packet = (PDRVMON_PACKET)MappedMdl.Address;
        //        KeAcquireInStackQueuedSpinLock(&dmctx.SharedMemorySpinLock, &LockHandle);

        //
        // Buffer to user mode.
        //
        if (ImageNameBuffer != NULL)
            _strcpy_w(Packet->DriverName, ImageNameBuffer);

        if (bDriverWhitelisted != FALSE) {  		          // set flag describing that driver is whitelisted
            Packet->Flags |= PACKET_FLAGS_DRIVER_WHITELISTED; // it will be displayed next in GUI as "This driver is in white list"
        }
        else {
            Packet->Flags &= ~PACKET_FLAGS_DRIVER_WHITELISTED;
        }

        KeSetEvent(dmctx.DataBufferReadyEvent, LOW_REALTIME_PRIORITY, FALSE);
        KeWaitForSingleObject(dmctx.DataBufferCompleteEvent, Executive, KernelMode, FALSE, NULL);

        //
        // Grab user mode answer, copy it to local variable, since shared memory is unsafe outside lock.
        //
        UserAnswer = Packet->UserAnswer;
        //KeReleaseInStackQueuedSpinLock(&LockHandle);

        //
        // User canceled driver loading, disallow it.
        //
        if (UserAnswer == DRVMON_IDNO) {

            Status = DmpDisallowCallback(
                ImageInfo, //BaseAddress from there 
                NULL,
                0,
                FALSE, //if user denied driver, then block it even if it in whitelist
                NULL);

            if (NT_SUCCESS(Status)) {
                _strcpy_w(dmctx.lpszLog, ImageNameBuffer);
                LogEvent(EVENT_TYPE_DRIVER_PATCHED, dmctx.lpszLog, 0);
            }
            else {
                LogEvent(EVENT_TYPE_DRV_ERROR, NULL, Status);
            }

        }
        else {
            //
            // User allowed driver loading.
            //
            _strcpy_w(dmctx.lpszLog, ImageNameBuffer);
            LogEvent(EVENT_TYPE_DRIVER_ALLOWED, dmctx.lpszLog, 0);
        }

        supFreeMappedMdl(&MappedMdl, FALSE);
    }
    return STATUS_SUCCESS;
}

/*
* DmpImageLoadHandler
*
* Purpose:
*
* Callback for LoadImage notify routine.
*
*/
VOID DmpImageLoadHandler(
    _In_ PUNICODE_STRING FullImageName,
    _In_ PIMAGE_INFO ImageInfo
)
{
    BOOLEAN CaptureEnabled = FALSE;
    BOOLEAN ManualFiltering = FALSE;
    BOOLEAN AutoFiltering = FALSE;
    BOOLEAN SilentApprove = FALSE;
    BOOLEAN bResult;

    LARGE_INTEGER CurrentTime;
    ULONG Value, Seed;

    //
    // Temporary buffer and it size.
    //
    SIZE_T NameBufferSize = PAGE_SIZE * 10;
    WCHAR *NameBuffer = NULL;

    //
    // Copy buffer and it size (will include output directory and generated random name).
    //
    SIZE_T CopyNameBufferSize = PAGE_SIZE * 11;
    WCHAR *CopyNameBuffer = NULL, *pCopyNameBufferPointer, *pJustFileName;

    //
    // Unicode string that will keep converted image filename.
    //
    UNICODE_STRING usImageName;

    //
    // Unicode strings for file copy.
    //
    UNICODE_STRING  usDstFile;
    UNICODE_STRING  usSrcFile;

    //
    // Used to form output to load driver event.
    //
    USHORT NtPrefix;

    //
    // Hash value and pointer to it.
    //
    UCHAR FileHash[SHA256_DIGEST_LENGTH];
    PVOID FileHashPointer = NULL;
    ULONG FileHashSize = 0;

    //
    // Output hash string for debug.
    //
    CHAR szOutHash[SHA256_HASH_STRING_LENGTH + 1];

    NTSTATUS Status;

    PAGED_CODE();


    UNREFERENCED_PARAMETER(ImageInfo);

#ifdef VERBOSE
    DbgPrint("[DM] DmpImageLoadHandler\n");
#endif

    //
    // Allocate memory for temporary buffer.
    //   
    NameBuffer = mmalloc(PagedPool, NameBufferSize);
    if (NameBuffer == NULL)
        return;

    RtlSecureZeroMemory(NameBuffer, NameBufferSize);

    //
    // Check capture driver bit set.
    //
    CaptureEnabled = ((dmctx.uFlags & DRVMON_CAPTURE_DRIVERS) > 0);

    //
    // Get real image name (process symlinks if required).
    //
    usImageName.Length = 0;
    usImageName.MaximumLength = (USHORT)NameBufferSize;
    usImageName.Buffer = NameBuffer;
    bResult = supGetFileImageName(FullImageName, &usImageName);
    if (bResult != FALSE) {

        //
        // Allocate memory for final copy buffer.
        //
        CopyNameBuffer = mmalloc(PagedPool, CopyNameBufferSize);
        if (CopyNameBuffer == NULL) {
            mmfree(NameBuffer);
            return;
        }
        RtlSecureZeroMemory(CopyNameBuffer, CopyNameBufferSize);

        //
        // Output log event - "Driver %s loading"
        //
        _strcpy_w(dmctx.lpszLog, NameBuffer);

#ifdef VERBOSE
        DbgPrint("[DM] DmpImageLoadHandler dmctx.lpszLog=%wS", dmctx.lpszLog);
#endif

        LogEvent(EVENT_TYPE_DRIVER_LOAD, dmctx.lpszLog, 0);
    }

    //
    // If CopyBuffer is allocated and Capturing enabled then collect driver.
    //
    if ((bResult != FALSE) && (CaptureEnabled != FALSE) && (CopyNameBuffer != NULL)) {

        //
        // Create path to save driver.
        // 1. Append output directory.
        //
        LOCK_DATA(&dmctx.OutputDirectoryMutex);
        _strcpy_w(CopyNameBuffer, dmctx.OutputDirectory);
        UNLOCK_DATA(&dmctx.OutputDirectoryMutex);

        pCopyNameBufferPointer = _strend_w(CopyNameBuffer);


        //
        // 2. Append current time + random value as text to filename.
        //
        KeQueryTickCount(&CurrentTime);

        Seed = ~CurrentTime.LowPart;
        Value = RtlRandomEx(&Seed);

        //
        //  Copy fileName format
        // 
        //  DM-HEX1-HEX2-OriginalName.OriginalExtension
        //
        //  Where:
        //     HEX1 is CurrentTime.LowPart
        //     HEX2 is pseudo-random value
        //

        RtlStringCchPrintfW(pCopyNameBufferPointer,
            MAX_PATH_DRV,
            L"DM-%08X-%08X-",
            CurrentTime.LowPart,
            Value);

        //
        // 3. Append real driver filename to the end.
        //
        pJustFileName = supJustFileName(NameBuffer);
        _strcat_w(CopyNameBuffer, pJustFileName);

#ifdef VERBOSE
        DbgPrint("[DM] CopyNameBuffer %wS", CopyNameBuffer);
#endif

        //
        // Copy file.
        //
        RtlInitUnicodeString(&usDstFile, CopyNameBuffer);
        RtlInitUnicodeString(&usSrcFile, NameBuffer);
        if (supCopyFile(&usDstFile, &usSrcFile)) {

            //
            // Report event "Driver copied".
            //
            NtPrefix = supIsNtNamePrefix(CopyNameBuffer, MAX_PATH_DRV);
            pCopyNameBufferPointer = &CopyNameBuffer[NtPrefix];
            _strcpy_w(dmctx.lpszLog, pCopyNameBufferPointer);
            LogEvent(EVENT_TYPE_DRIVER_COLLECTED, dmctx.lpszLog, 0);
        }
        else {
            //
            // Error copy file, report event.
            //
            LogEvent(EVENT_TYPE_DRV_ERROR, NULL, 0);
        }
    }

    //
    // If Manual-load control enabled then proceed with flt callback.
    //
    ManualFiltering = ((dmctx.uFlags & DRVMON_FILTER_ENABLED) > 0);
    AutoFiltering = ((dmctx.uFlags & DRVMON_BLOCK_DRIVERS_LOADING) > 0);

    //
    // If any filtering is enabled, then hash file.
    //
    if ((ManualFiltering != FALSE) || (AutoFiltering != FALSE)) {

        RtlSecureZeroMemory(&FileHash, sizeof(FileHash));

        RtlInitUnicodeString(&usSrcFile, NameBuffer);
        bResult = supHashFile(&usSrcFile, &FileHash, sizeof(FileHash), supSha256Buffer);
        if (bResult != FALSE) {
            FileHashPointer = &FileHash;
            FileHashSize = SHA256_DIGEST_LENGTH;
            RtlSecureZeroMemory(szOutHash, sizeof(szOutHash));
            supPrintHash((PUCHAR)&FileHash, FileHashSize, (PUCHAR)&szOutHash, SHA256_HASH_STRING_LENGTH);

#ifdef VERBOSE
            DbgPrint("[DM] Hash = %s, FileHashPointer = %p, FileHashSize = %u", szOutHash, FileHashPointer, FileHashSize);
#endif

        }
        else {
            FileHashSize = 0;
            FileHashPointer = NULL;
        }
    }

    //
    // Run filter callback if manual filtering is ON.
    //
    if (ManualFiltering) {

        Status = DmpLoadFilterCallback(
            NameBuffer,
            ImageInfo,
            FileHashPointer,
            FileHashSize);

#ifdef VERBOSE
        DbgPrint("[DM] DmpLoadFilterCallback = %lx", Status);
#endif

        goto RoutineEnd;

    }

    //
    // Driver loading block enabled run disallow callback.
    //
    if (AutoFiltering) {

        Status = DmpDisallowCallback(
            ImageInfo,
            FileHashPointer,
            FileHashSize,
            TRUE, //use whitelist.
            &SilentApprove);

#ifdef VERBOSE
        DbgPrint("DmpDisallowCallback = %lx", Status);
#endif

        switch (Status) {
            //whitelisted
        case STATUS_VALID_IMAGE_HASH:
            //
            // If SilentApprove is FALSE then report back usermode event.
            //
            if (SilentApprove == FALSE) {
                if (CopyNameBuffer) {
                    _strcpy_w(dmctx.lpszLog, CopyNameBuffer);
                }
                else {
                    _strcpy_w(dmctx.lpszLog, UnknownDrv);
                }
                LogEvent(EVENT_TYPE_DRIVER_ALLOWED, dmctx.lpszLog, 0);
            }
            break;
            //blocked
        case STATUS_SUCCESS:
            if (CopyNameBuffer) {
                _strcpy_w(dmctx.lpszLog, CopyNameBuffer);
            } 
            else {
                _strcpy_w(dmctx.lpszLog, UnknownDrv);
            }
            LogEvent(EVENT_TYPE_DRIVER_PATCHED, dmctx.lpszLog, 0);
            break;

            //any other status considered as error
        default:
            LogEvent(EVENT_TYPE_DRV_ERROR, NULL, Status);
            break;
        }

    }

RoutineEnd:
    //
    // Finally release memory.
    //
    if (CopyNameBuffer != NULL) {
        mmfree(CopyNameBuffer);
    }
    mmfree(NameBuffer);
}

/*
* DmLoadImageNotifyRoutine
*
* Purpose:
*
* Image load notify callback.
*
*/
VOID DmLoadImageNotifyRoutine(
    _In_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
)
{
    PAGED_CODE();

    // If DrvMon process not available or this is not driver then skip.
    if ((dmctx.IsShutdown != FALSE) || (ProcessId != 0))
        return;

    //
    // Sanity checking.
    //
    if (FullImageName == NULL)
        return;
    if (FullImageName->Buffer == NULL)
        return;
    if ((FullImageName->Length == 0) || (FullImageName->MaximumLength == 0))
        return;

#ifdef VERBOSE    
    DbgPrint("ProcessId=%p,\nImageInfo->ImageAddressingMode=%lu,\nImageInfo->SystemModeImage = %lu,\nImageInfo->ImageMappedToAllPids = %lu,\n\
ImageInfo->ExtendedInfoPresent = %lu,\nImageInfo->MachineTypeMismatch = %lu,\nImageInfo->ImageSignatureLevel = %lu,\nImageInfo->ImageSignatureType = %lu",
ProcessId,
ImageInfo->ImageAddressingMode,
ImageInfo->SystemModeImage,
ImageInfo->ImageMappedToAllPids,
ImageInfo->ExtendedInfoPresent,
ImageInfo->MachineTypeMismatch,
ImageInfo->ImageSignatureLevel,
ImageInfo->ImageSignatureType);
#endif

    //
    // Execute actual handler.
    //
    DmpImageLoadHandler(FullImageName, ImageInfo);
}

/*
* DmProcessNotifyRoutine
*
* Purpose:
*
* Process notify callback, registered to detect DrvMon process shutdown.
*
*/
VOID NTAPI DmProcessNotifyRoutine(
    _In_ HANDLE  ParentId,
    _In_ HANDLE  ProcessId,
    _In_ BOOLEAN  Create
)
{
    PEPROCESS CurrentProcess;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(ParentId);
    UNREFERENCED_PARAMETER(ProcessId);

    if (Create == FALSE) {
        CurrentProcess = PsGetCurrentProcess();
        if (CurrentProcess == dmctx.DrvMonProcess) {
            dmctx.IsShutdown = TRUE;
            KeSetEvent(dmctx.DataBufferCompleteEvent, LOW_REALTIME_PRIORITY, FALSE);
        }
    }
}

/*
* DmpFreeGlobals
*
* Purpose:
*
* Free global allocated resources.
*
*/
VOID DmpFreeGlobals(
    VOID
)
{
    PAGED_CODE();

    if (dmctx.ImageNotifyInstalled != FALSE) {
        PsRemoveLoadImageNotifyRoutine(
            (PLOAD_IMAGE_NOTIFY_ROUTINE)DmLoadImageNotifyRoutine);
        dmctx.ImageNotifyInstalled = FALSE;
    }

    if (dmctx.ProcessNotifyInstalled != FALSE) {
        PsSetCreateProcessNotifyRoutine(
            (PCREATE_PROCESS_NOTIFY_ROUTINE)&DmProcessNotifyRoutine, TRUE);
        dmctx.ProcessNotifyInstalled = FALSE;
    }

    KnownDriversDestroy();

    if (dmctx.DataBufferReadyEvent != NULL) {
        ObfDereferenceObject(dmctx.DataBufferReadyEvent);
        dmctx.DataBufferReadyEvent = NULL;
    }
    if (dmctx.DataBufferCompleteEvent != NULL) {
        ObfDereferenceObject(dmctx.DataBufferCompleteEvent);
        dmctx.DataBufferCompleteEvent = NULL;
    }
    if (dmctx.SharedMemory != NULL) {
        ZwUnmapViewOfSection(ZwCurrentProcess(), dmctx.SharedMemory);
        dmctx.SharedMemory = NULL;
    }

    if (dmctx.lpszLog != NULL) {
        mmfree(dmctx.lpszLog);
        dmctx.lpszLog = NULL;
    }
}

/*
* DriverUnload
*
* Purpose:
*
* Driver unload procedure.
*
*/
VOID DriverUnload(
    _In_  struct _DRIVER_OBJECT *DriverObject
)
{
    PAGED_CODE();

#ifdef VERBOSE
    DbgPrint("[DM] Unload.\n");
#endif

    DmpFreeGlobals();

    IoDeleteDevice(DriverObject->DeviceObject);
}

/*
* DmpInit
*
* Purpose:
*
* Initialize global variables.
*
*/
NTSTATUS DmpInit(
    VOID
)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    SIZE_T ViewSize = SHARED_SPACE_SIZE;
    HANDLE hSection = NULL;
    LARGE_INTEGER MaximumSize;
    UNICODE_STRING EventName;
    UNICODE_STRING SectionName;
    OBJECT_ATTRIBUTES attr;

    LogInit();

    //
    //  Open DataReadyEvent.
    //
    RtlInitUnicodeString(&EventName, Event1Name);
    Status = ObReferenceObjectByName(
        &EventName,
        OBJ_CASE_INSENSITIVE,
        NULL,
        0,
        *ExEventObjectType,
        KernelMode,
        NULL,
        (PVOID *)&dmctx.DataBufferReadyEvent);

    if (!NT_SUCCESS(Status)) {

#ifdef VERBOSE
        DbgPrint("[DM] ObReferenceObjectByName(DataReadyEvent) %lx.\n", Status);
#endif

        return Status;
    }

    //
    // Open DataBufferCompleteEvent.
    //
    RtlInitUnicodeString(&EventName, Event2Name);
    Status = ObReferenceObjectByName(
        &EventName,
        OBJ_CASE_INSENSITIVE,
        NULL,
        0,
        *ExEventObjectType,
        KernelMode,
        NULL,
        (PVOID *)&dmctx.DataBufferCompleteEvent);

    if (!NT_SUCCESS(Status)) {

#ifdef VERBOSE
        DbgPrint("[DM] ObReferenceObjectByName(DataCompleteEvent) %lx.\n", Status);
#endif

        ObfDereferenceObject(dmctx.DataBufferReadyEvent);
        return Status;
    }

    //
    // Open and map shared section.
    //
    RtlInitUnicodeString(&SectionName, SharedSectionName);
    InitializeObjectAttributes(&attr, &SectionName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    Status = ZwOpenSection(
        &hSection,
        SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_QUERY,
        &attr);

    if (NT_SUCCESS(Status)) {

        MaximumSize.QuadPart = SHARED_SPACE_SIZE;
        dmctx.SharedMemory = NULL;

        Status = ZwMapViewOfSection(
            hSection,
            ZwCurrentProcess(),
            &dmctx.SharedMemory,
            0,
            SHARED_SPACE_SIZE,
            NULL,
            &ViewSize,
            ViewUnmap,
            MEM_TOP_DOWN,
            PAGE_READWRITE);

        ZwClose(hSection);
    }
    else {
#ifdef VERBOSE
        DbgPrint("[DM] ZwOpenSection(SharedSection) %lx.\n", Status);
#endif

        ObfDereferenceObject(dmctx.DataBufferReadyEvent);
        ObfDereferenceObject(dmctx.DataBufferCompleteEvent);
    }
    return Status;
}

/*
* DmpProbeAndReadOutputDirectory
*
* Purpose:
*
* Copy input UNICODE_STRING to dmctx.OutputDirectory.
*
*/
NTSTATUS DmpProbeAndReadOutputDirectory(
    _In_ PDM_SET_OUTDIR InputSetOutDir
)
{
    NTSTATUS Status = STATUS_INVALID_PARAMETER;

    __try {

        if (InputSetOutDir->usOutputDirectory.Length >= sizeof(dmctx.OutputDirectory))
            return STATUS_BUFFER_OVERFLOW;

        ProbeForRead(InputSetOutDir->usOutputDirectory.Buffer,
            InputSetOutDir->usOutputDirectory.Length,
            sizeof(WCHAR));

        LOCK_DATA(&dmctx.OutputDirectoryMutex);

        RtlCopyMemory(dmctx.OutputDirectory,
            InputSetOutDir->usOutputDirectory.Buffer,
            InputSetOutDir->usOutputDirectory.Length);

#ifdef VERBOSE
        DbgPrint("[DM] IOCTL_DRVMON_SETOUTPUT_DIRECTORY, OutputDirectory = %wS", dmctx.OutputDirectory);
#endif

        UNLOCK_DATA(&dmctx.OutputDirectoryMutex);

        Status = STATUS_SUCCESS;

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
    }

    return Status;
}

/*
* DmpWhiteListHandler
*
* Purpose:
*
* Handle whitelist usermode requests.
*
*/
NTSTATUS DmpWhiteListHandler(
    _In_ PDM_WL_PACKET WLPacket,
    _In_ BOOLEAN fRemoveEntry
)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    SIZE_T cbString;

    KDRVPACKET Packet;

    if (fRemoveEntry) {

        RtlCopyMemory(&Packet.DriverName, WLPacket->DriverName, sizeof(WLPacket->DriverName));
        RtlCopyMemory(&Packet.HashValue, WLPacket->Hash, sizeof(WLPacket->Hash));

        if (KnownDriversRemoveEntry(WLPacket->Tag, &Packet)) {

#ifdef VERBOSE
            DbgPrint("[DM] KnownDriversRemoveEntry Success\n");
#endif

            Status = STATUS_SUCCESS;
        }
        else {

#ifdef VERBOSE
            DbgPrint("[DM] KnownDriversRemoveEntry Failed\n");
#endif

            Status = STATUS_UNSUCCESSFUL;
        }
    }
    else {

        cbString = _strlen_w(WLPacket->DriverName) * sizeof(WCHAR);
        if (cbString == 0)
            return STATUS_INVALID_BUFFER_SIZE;

        if (KnownDriversAddEntry(
            WLPacket->Tag,
            WLPacket->Flags,
            WLPacket->DriverName,
            cbString,
            WLPacket->Hash,
            sizeof(WLPacket->Hash)))
        {

#ifdef VERBOSE
            DbgPrint("[DM] KnownDriversAddEntry Success\n");
#endif

            Status = STATUS_SUCCESS;
        }
        else {

#ifdef VERBOSE
            DbgPrint("[DM] KnownDriversAddEntry Failed\n");
#endif

            Status = STATUS_UNSUCCESSFUL;
        }
    }
    return Status;
}

/*
* DevioctlDispatch
*
* Purpose:
*
* IRP_MJ_DEVICE_CONTROL dispatch.
*
*/
NTSTATUS DevioctlDispatch(
    _In_ struct _DEVICE_OBJECT *DeviceObject,
    _Inout_ struct _IRP *Irp
)
{
    NTSTATUS            Status = STATUS_UNSUCCESSFUL;
    ULONG               bytesIO = 0;
    PIO_STACK_LOCATION  StackLocation;

    PVOID               OriginalInput;
    ULONG               InputLength;
    ULONG               IoControlCode;

    PDM_SET_FLAG        InputSetFlag;
    PDM_SET_OUTDIR      InputSetOutDir;
    PDM_WL_PACKET       InputWLPacket;

    PVOID               CapturedInputPointer;
    UCHAR               CapturedInput[DM_MAXIMUM_INPUT_SIZE];


    UNREFERENCED_PARAMETER(DeviceObject);

    PAGED_CODE();

    //
    // Allow only user mode calls.
    //
    if (Irp->RequestorMode != UserMode) {
        Status = STATUS_INVALID_DEVICE_REQUEST;
        goto DispatchEnd;
    }

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    if (StackLocation == NULL) {
        Status = STATUS_INTERNAL_ERROR;
        goto DispatchEnd;
    }

    IoControlCode = StackLocation->Parameters.DeviceIoControl.IoControlCode;
    OriginalInput = StackLocation->Parameters.DeviceIoControl.Type3InputBuffer;
    InputLength = StackLocation->Parameters.DeviceIoControl.InputBufferLength;

    //
    // Sanity check over user mode buffer.
    //

    // 1. Make sure input buffer present and it size is not 0.
    if ((InputLength != 0) && (!OriginalInput)) {
        Status = STATUS_INVALID_BUFFER_SIZE;
        goto DispatchEnd;
    }

    // 2. Make sure caller supplied buffer is not exceed maximum allowed length.
    if (InputLength > DM_MAXIMUM_INPUT_SIZE) {
        Status = STATUS_INVALID_BUFFER_SIZE;
        goto DispatchEnd;
    }

    // 3. Copy input buffer to internal buffer in safe way.
    __try {
        ProbeForRead(OriginalInput, InputLength, sizeof(UCHAR));
        memcpy(CapturedInput, OriginalInput, InputLength);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
        goto DispatchEnd;
    }

    CapturedInputPointer = CapturedInput;

    switch (IoControlCode) {

        //-------------------------------------------------------------------------
        //           Change internal flags.
        //-------------------------------------------------------------------------

    case IOCTL_DRVMON_SET_FLAGS:

        InputSetFlag = (PDM_SET_FLAG)CapturedInputPointer;
        if (InputSetFlag->cb != sizeof(DM_SET_FLAG)) {
            Status = STATUS_INVALID_PARAMETER;
            break;
        }
        InterlockedExchange((PLONG)&dmctx.uFlags, InputSetFlag->DrvMonFlag);

#ifdef VERBOSE
        DbgPrint("[DM] IOCTL_DRVMON_SET_FLAGS, uFlags = %lu.\n", dmctx.uFlags);
#endif

        Status = STATUS_SUCCESS;
        break;


        //-------------------------------------------------------------------------
        //          Change default output directory to user-defined.
        //-------------------------------------------------------------------------

    case IOCTL_DRVMON_SETOUTPUT_DIRECTORY:

        InputSetOutDir = (PDM_SET_OUTDIR)CapturedInputPointer;
        if (InputSetOutDir->cb != sizeof(DM_SET_OUTDIR)) {
            Status = STATUS_INVALID_PARAMETER;
            break;
        }

        Status = DmpProbeAndReadOutputDirectory(InputSetOutDir);
        break;

        //-------------------------------------------------------------------------
        //           Add entry to white list.
        //-------------------------------------------------------------------------

    case IOCTL_DRVMON_ADDWLENTRY:

#ifdef VERBOSE
        DbgPrint("[DM] IOCTL_DRVMON_ADDWLENTRY\n");
#endif

        InputWLPacket = (PDM_WL_PACKET)CapturedInputPointer;
        if (InputWLPacket->cb != sizeof(DM_WL_PACKET)) {
            Status = STATUS_INVALID_PARAMETER;
            break;
        }

        Status = DmpWhiteListHandler(InputWLPacket, FALSE);
        break;

        //-------------------------------------------------------------------------
        //           Delete entry from white list.
        //-------------------------------------------------------------------------

    case IOCTL_DRVMON_REMOVEWLENTRY:

#ifdef VERBOSE
        DbgPrint("[DM] IOCTL_DRVMON_REMOVEWLENTRY\n");
#endif

        InputWLPacket = (PDM_WL_PACKET)CapturedInputPointer;
        if (InputWLPacket->cb != sizeof(DM_WL_PACKET)) {
            Status = STATUS_INVALID_PARAMETER;
            break;
        }

        Status = DmpWhiteListHandler(InputWLPacket, TRUE);
        break;

    default:
        Status = STATUS_INVALID_PARAMETER;
    };

DispatchEnd:
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = bytesIO;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

/*
* UnsupportedDispatch
*
* Purpose:
*
* Unused IRP_MJ_* dispatch.
*
*/
NTSTATUS UnsupportedDispatch(
    _In_ struct _DEVICE_OBJECT *DeviceObject,
    _Inout_ struct _IRP *Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PAGED_CODE();

    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_NOT_SUPPORTED;
}

/*
* CreatDispatch
*
* Purpose:
*
* IRP_MJ_CREATE dispatch.
*
*/
NTSTATUS CreateDispatch(
    _In_ struct _DEVICE_OBJECT *DeviceObject,
    _Inout_ struct _IRP *Irp
)
{
    NTSTATUS Status = STATUS_CONNECTION_ABORTED;
    PVOID CurrentProcess;

    UNREFERENCED_PARAMETER(DeviceObject);

    PAGED_CODE();

#ifdef VERBOSE
    DbgPrint("[DM] Open\n");
#endif

    //
    // Remember Process on connect.
    // Note: we are using Exclusive device flag on IoCreateDevice.
    // I/O Manager will always return STATUS_ACCESS_DENIED 
    // on attempt to open more than one handle to our device.
    //
    // However already connected check present here for future use.
    //
    if (dmctx.DrvMonProcess == NULL) {
        Status = LogOpenPipe();
        CurrentProcess = PsGetCurrentProcess();
        InterlockedExchangePointer(&dmctx.DrvMonProcess, CurrentProcess);

#ifdef VERBOSE
        DbgPrint("[DM] Client connected = %p\n", dmctx.DrvMonProcess);
#endif

    }
    else {
        Status = STATUS_CONNECTION_ABORTED;

#ifdef VERBOSE
        DbgPrint("[DM] Client already connected = %p\n", dmctx.DrvMonProcess);
#endif

    }

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

/*
* CloseDispatch
*
* Purpose:
*
* IRP_MJ_CLOSE dispatch.
*
*/
NTSTATUS CloseDispatch(
    _In_ struct _DEVICE_OBJECT *DeviceObject,
    _Inout_ struct _IRP *Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PAGED_CODE();

#ifdef VERBOSE    
    DbgPrint("[DM] Close.\n");
#endif

    if (dmctx.DrvMonProcess != NULL) {

#ifdef VERBOSE
        DbgPrint("[DM] DrvMonProcess disconnected = %p\n", dmctx.DrvMonProcess);
#endif

        InterlockedExchangePointer(&dmctx.DrvMonProcess, NULL);
    }

    LogClose();

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/*
* DriverEntry
*
* Purpose:
*
* Tsugumi entry point.
*
*/
NTSTATUS DriverEntry(
    _In_  struct _DRIVER_OBJECT *DriverObject,
    _In_  PUNICODE_STRING RegistryPath
)
{
    BOOLEAN bCond = FALSE;
    NTSTATUS Status;
    SIZE_T memIO;
    DEVICE_OBJECT *DeviceObject = NULL;
    HANDLE hDevice = NULL;
    UNICODE_STRING DeviceName;

    UNREFERENCED_PARAMETER(RegistryPath);

#ifdef VERBOSE
    DbgPrint("[DM] DriverEntry\n");
#endif

    RtlSecureZeroMemory(&dmctx, sizeof(DRVMONCONTEXT));


    //
    // Initialize known drivers variables.
    //
    KnownDriversCreate();

    //
    // Initialize logger related variables.
    //
    KeInitializeMutex(&dmctx.LogMutex, 0);
    KeInitializeMutex(&dmctx.OutputDirectoryMutex, 0);

    //dmctx.SharedMemorySpinLock = 0;

    //
    // Set default output directory.
    //
    _strcpy_w(dmctx.OutputDirectory, L"\\SystemRoot\\TEMP\\");

    //
    // Allocate memory for output log global variable.
    //
    memIO = PAGE_SIZE * 16;
    dmctx.lpszLog = (LPWSTR)mmalloc(NonPagedPoolCacheAligned, memIO);
    if (dmctx.lpszLog == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    else {
        RtlSecureZeroMemory(dmctx.lpszLog, memIO);
    }

    //
    // Initialize shared section and data completion events.
    //
    Status = DmpInit();
    if (!NT_SUCCESS(Status)) {
        mmfree(dmctx.lpszLog);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    do {

        //
        // Create device.
        //
        RtlInitUnicodeString(&DeviceName, DRVMON_DEV_OBJECT);
        Status = IoCreateDevice(
            DriverObject,
            0, &DeviceName,
            FILE_DEVICE_UNKNOWN,
            FILE_DEVICE_SECURE_OPEN,
            TRUE,
            &DeviceObject);

        if (!NT_SUCCESS(Status)) {

#ifdef VERBOSE
            DbgPrint("[DM] IoCreateDevice(Sendai) %lx\n", Status);
#endif

            break;
        }

        DriverObject->DriverUnload = (PDRIVER_UNLOAD)&DriverUnload;

        //
        // Set access mode to device object, allow only admins.
        //
        if (NT_SUCCESS(ObOpenObjectByPointer(
            DeviceObject,
            OBJ_KERNEL_HANDLE,
            NULL,
            GENERIC_ALL,
            NULL,
            KernelMode,
            &hDevice)))
        {
            supSetDefaultSecurity(hDevice);
            ZwClose(hDevice);
        }

        //
        // Set our process shutdown notification.
        //
        Status = PsSetCreateProcessNotifyRoutine(
            (PCREATE_PROCESS_NOTIFY_ROUTINE)&DmProcessNotifyRoutine,
            FALSE);

#ifdef VERBOSE
        if (!NT_SUCCESS(Status)) {
            DbgPrint("[DM] PsSetCreateProcessNotifyRoutine %lx\n", Status);
        }
#endif

        if (NT_SUCCESS(Status)) {

            //
            //  Set image load notify routine.
            //
            dmctx.ProcessNotifyInstalled = TRUE;
            Status = PsSetLoadImageNotifyRoutine(
                (PLOAD_IMAGE_NOTIFY_ROUTINE)DmLoadImageNotifyRoutine);

#ifdef VERBOSE
            if (!NT_SUCCESS(Status)) {
                DbgPrint("[DM] PsSetLoadImageNotifyRoutine %lx\n", Status);
            }
#endif

            if (NT_SUCCESS(Status)) {
                dmctx.ImageNotifyInstalled = TRUE;
                DriverObject->MajorFunction[IRP_MJ_CREATE] = &CreateDispatch;
                DriverObject->MajorFunction[IRP_MJ_CLOSE] = &CloseDispatch;
                DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = &DevioctlDispatch;
                DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
            }
        }

    } while (bCond);

    //
    // Something went wrong during initialization.
    //
    if (!NT_SUCCESS(Status)) {
        DmpFreeGlobals();
    }

#ifdef VERBOSE
    DbgPrint("[DM] DriverEntry Exit = %lx\n", Status);
#endif

    return Status;
}
