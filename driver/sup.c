/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2010 - 2018
*
*  TITLE:       SUP.C
*
*  VERSION:     3.01
*
*  DATE:        10 Nov 2018
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "drvmon.h"

const ALIGNEDNAME ObpDosDevicesShortNamePrefix = { L'\\',L'?',L'?',L'\\' }; // L"\??\"
const UNICODE_STRING ObpDosDevicesShortName = {
    sizeof(ObpDosDevicesShortNamePrefix),
    sizeof(ObpDosDevicesShortNamePrefix),
    (PWSTR)&ObpDosDevicesShortNamePrefix
};

static CHAR supConvertTableUpperCase[] =
"0123456789" /* 0 - 9 */
"ABCDEFGHIJKLMNOPQRSTUVWXYZ" /* 10 - 35 */
" !\"#$%&'()*+,-./" /* 36 - 51 */
":;<=>?@" /* 52 - 58 */
"[\\]^_`" /* 59 - 64 */
"{|}~" /* 65 - 68 */
;

/*
* align
*
* Purpose:
*
* Align value X to Base.
*
*/
ULONG_PTR align(
    ULONG_PTR x,
    ULONG_PTR base
)
{
    ULONG_PTR y = x % base;
    if (y == 0) return x;
    y = (x - y);
    return y + base;
}

/*
* supSetDefaultSecurity
*
* Purpose:
*
* Set security access rights System/Admin for specified by handle object.
*
*/
NTSTATUS supSetDefaultSecurity(
    _In_ HANDLE hObject
)
{
    BOOLEAN                  bCond = FALSE;
    SID_IDENTIFIER_AUTHORITY Authority = SECURITY_NT_AUTHORITY;
    PSID                     AdmSid = NULL;
    PSID                     SysSid = NULL;
    PACL                     SysAcl = NULL;
    ULONG                    DaclSize = 0;
    NTSTATUS                 Result;
    SECURITY_DESCRIPTOR      SecurityDescriptor;

    Result = STATUS_UNSUCCESSFUL;

    do {

        //
        // Allocate Sid for Admin and System
        //
        AdmSid = mmalloc(NonPagedPoolCacheAligned, RtlLengthRequiredSid(2));
        SysSid = mmalloc(NonPagedPoolCacheAligned, RtlLengthRequiredSid(1));

        if ((AdmSid == NULL) || (SysSid == NULL)) {
            Result = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        //
        // Set Rid for Admin Sid.
        //
        if (NT_SUCCESS(RtlInitializeSid(AdmSid, &Authority, 2))) {
            *RtlSubAuthoritySid(AdmSid, 0) = SECURITY_BUILTIN_DOMAIN_RID;
            *RtlSubAuthoritySid(AdmSid, 1) = DOMAIN_ALIAS_RID_ADMINS;
        }
        else {
            Result = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        //
        // Set Rid for System Sid.
        //
        if (NT_SUCCESS(RtlInitializeSid(SysSid, &Authority, 1))) {
            *RtlSubAuthoritySid(SysSid, 0) = SECURITY_LOCAL_SYSTEM_RID;
        }
        else {
            Result = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        //
        // Allocate memory for ACL.
        //
        DaclSize = sizeof(ACL) + (2 * sizeof(ACCESS_ALLOWED_ACE)) +
            SeLengthSid(AdmSid) + SeLengthSid(SysSid) + 8;

        if ((SysAcl = (PACL)mmalloc(NonPagedPoolCacheAligned, DaclSize)) == NULL) {
            Result = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        //
        // Create ACL and add Admin/System Sid to it.
        //
        Result = RtlCreateAcl(SysAcl, DaclSize, ACL_REVISION);
        if (!NT_SUCCESS(Result))
            break;

        Result = RtlAddAccessAllowedAce(
            SysAcl, ACL_REVISION, GENERIC_ALL, SysSid);
        if (!NT_SUCCESS(Result))
            break;

        Result = RtlAddAccessAllowedAce(
            SysAcl, ACL_REVISION, GENERIC_ALL, AdmSid);
        if (!NT_SUCCESS(Result))
            break;

        //
        // Create security descriptor.
        //
        Result = RtlCreateSecurityDescriptor(&SecurityDescriptor,
            SECURITY_DESCRIPTOR_REVISION1);
        if (!NT_SUCCESS(Result))
            break;

        //
        // Set Acl to security descriptor.
        //
        Result = RtlSetDaclSecurityDescriptor(&SecurityDescriptor,
            TRUE, SysAcl, FALSE);
        if (!NT_SUCCESS(Result))
            break;

        //
        // Finally set new security descriptor for our object.
        //
        Result = ZwSetSecurityObject(hObject, DACL_SECURITY_INFORMATION,
            &SecurityDescriptor);

    } while (bCond);

    if (SysAcl != NULL) mmfree(SysAcl);
    if (AdmSid != NULL) mmfree(AdmSid);
    if (SysSid != NULL) mmfree(SysSid);

    return Result;
}

/*
* supFileExists
*
* Purpose:
*
* Return TRUE if the given exist on device.
*
*/
BOOLEAN supFileExists(
    _In_ PUNICODE_STRING FileName
)
{
    NTSTATUS Status;
    BOOLEAN bResult, IsDirectory;
    OBJECT_ATTRIBUTES attr;
    FILE_NETWORK_OPEN_INFORMATION fna;

    if (!ARGUMENT_PRESENT(FileName))
        return FALSE;

    RtlSecureZeroMemory(&fna, sizeof(FILE_NETWORK_OPEN_INFORMATION));

    bResult = FALSE;
    InitializeObjectAttributes(&attr, FileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    Status = ZwQueryFullAttributesFile(&attr, &fna);
    if (NT_SUCCESS(Status)) {
        IsDirectory = ((fna.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) > 0);
        if ((fna.FileAttributes != 0xFFFFFFFF) && (IsDirectory == FALSE)) {
            bResult = TRUE;
        }
        return bResult;
    }
    return FALSE;
}

/*
* supIsSymbolicLink
*
* Purpose:
*
* Return TRUE is the given file path is a symbolic link.
*
*/
BOOLEAN supIsSymbolicLink(
    _In_ PUNICODE_STRING FileName
)
{
    NTSTATUS Status;
    OBJECT_ATTRIBUTES attr;
    HANDLE LinkHandle;

    if (!ARGUMENT_PRESENT(FileName))
        return FALSE;

    LinkHandle = NULL;
    InitializeObjectAttributes(&attr, FileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    Status = ZwOpenSymbolicLinkObject(&LinkHandle, SYMBOLIC_LINK_QUERY, &attr);
    if (NT_SUCCESS(Status)) {
        ZwClose(LinkHandle);
        return TRUE;
    }
    return FALSE;
}

/*
* supCreateMappedMdl
*
* Purpose:
*
* Allocate mapped Mdl.
*
*/
NTSTATUS supCreateMappedMdl(
    _In_ PVOID Address,
    _In_ ULONG Length,
    _Out_ MAPPED_MDL *MappedMdl,
    _In_ BOOLEAN  IsKernelMode
)
{
    PMDL mdl;
    NTSTATUS Status = STATUS_SUCCESS;
    MappedMdl->Mdl = NULL;
    MappedMdl->Address = NULL;

    mdl = IoAllocateMdl(Address, Length, FALSE, FALSE, NULL);
    if (mdl == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (IsKernelMode != FALSE) {

        MmBuildMdlForNonPagedPool(mdl);
#pragma warning(suppress: 28145)
        mdl->MdlFlags |= MDL_MAPPED_TO_SYSTEM_VA;

        MappedMdl->Address = MmMapLockedPagesSpecifyCache(
            mdl,
            KernelMode,
            MmNonCached,
            NULL,
            FALSE,
            HighPagePriority
        );

    }
    else {

        __try {

            MmProbeAndLockPages(mdl, KernelMode, IoModifyAccess);
            MappedMdl->Address = MmMapLockedPagesSpecifyCache(
                mdl,
                KernelMode,
                MmCached,
                NULL,
                FALSE,
                NormalPagePriority
            );

        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            Status = GetExceptionCode();
        }
    }

    MappedMdl->Mdl = mdl;
    if (!MappedMdl->Address) {
        supFreeMappedMdl(MappedMdl, IsKernelMode);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    return Status;
}

/*
* supFreeMappedMdl
*
* Purpose:
*
* Free resources associated with mdl.
*
*/
VOID supFreeMappedMdl(
    _In_ MAPPED_MDL *MappedMdl,
    _In_ BOOLEAN IsKernelMode
)
{
    if (MappedMdl->Mdl != NULL) {
        if (MappedMdl->Address != NULL) {
            if (IsKernelMode != FALSE) {
                MmUnmapLockedPages(MappedMdl->Address, MappedMdl->Mdl);
            }
            else {
                MmUnlockPages(MappedMdl->Mdl);
            }
            MappedMdl->Address = NULL;
        }
        IoFreeMdl(MappedMdl->Mdl);
        MappedMdl->Mdl = NULL;
    }
}

/*
* supGetFileSize
*
* Purpose:
*
* Kernel mode GetFileSize.
*
*/
BOOLEAN supGetFileSize(
    _In_ HANDLE hFile,
    _Inout_opt_ PULONG pLowPart,
    _Inout_opt_ PULONG pHighPart
)
{
    IO_STATUS_BLOCK iost;
    FILE_STANDARD_INFORMATION fsi;
    NTSTATUS Status;

    Status = ZwQueryInformationFile(hFile, &iost, &fsi,
        sizeof(FILE_STANDARD_INFORMATION),
        FileStandardInformation);

    if (!NT_SUCCESS(Status))
        return FALSE;

    if (ARGUMENT_PRESENT(pLowPart))
        *pLowPart = fsi.EndOfFile.LowPart;

    if (ARGUMENT_PRESENT(pHighPart))
        *pHighPart = fsi.EndOfFile.HighPart;

    return TRUE;
}

/*
* supCopyFile
*
* Purpose:
*
* Create copy of given file with new name.
*
*/
BOOLEAN supCopyFile(
    _In_ PUNICODE_STRING DstFile,
    _In_ PUNICODE_STRING SrcFile
)
{
    BOOLEAN bRet = FALSE, bCond = FALSE;
    NTSTATUS Status;
    ULONG uLength = 0;
    SIZE_T BufferSize = 0;
    PVOID  DataBuffer = NULL;
    HANDLE hSrcFile = NULL;
    HANDLE hDstFile = NULL;

    OBJECT_ATTRIBUTES  Obja;
    IO_STATUS_BLOCK iost;

    uLength = 0L;
    bRet = FALSE;

    if ((!ARGUMENT_PRESENT(SrcFile)) ||
        (!ARGUMENT_PRESENT(DstFile)))
    {
        return FALSE;
    }

    do {

        //
        // Open input file.
        //
        InitializeObjectAttributes(&Obja, SrcFile, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

        Status = ZwOpenFile(
            &hSrcFile,
            FILE_READ_ACCESS | SYNCHRONIZE,
            &Obja, &iost,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);

        if (!NT_SUCCESS(Status)) {
            LogEvent(EVENT_TYPE_DRV_ERROR, NULL, Status);
            break;
        }

        //
        // Create buffer of exact file size.
        //
        if (supGetFileSize(hSrcFile, &uLength, NULL) == FALSE) {
            LogEvent(EVENT_TYPE_DRV_ERROR, NULL, Status);
            break;
        }

        BufferSize = align((ULONG_PTR)uLength, PAGE_SIZE);
        DataBuffer = ExAllocatePoolWithTag(
            PagedPool,
            BufferSize,
            TAG_DRVMON_ENTRY);

        if (DataBuffer == NULL) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            LogEvent(EVENT_TYPE_DRV_ERROR, NULL, Status);
            break;
        }

        //
        // Read file to buffer.
        //
        Status = ZwReadFile(
            hSrcFile,
            NULL,
            NULL,
            NULL,
            &iost,
            DataBuffer,
            uLength,
            NULL,
            NULL);

        if (!NT_SUCCESS(Status)) {
            LogEvent(EVENT_TYPE_DRV_ERROR, NULL, Status);
            break;
        }

        //
        // Create output file.
        //
        InitializeObjectAttributes(&Obja, DstFile, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
        Status = ZwCreateFile(&hDstFile,
            FILE_WRITE_ACCESS | SYNCHRONIZE,
            &Obja, &iost,
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            0,
            FILE_OVERWRITE_IF,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            NULL, 0);

        if (!NT_SUCCESS(Status)) {
            LogEvent(EVENT_TYPE_DRV_ERROR, NULL, Status);
            break;
        }

        //
        // Write buffer to file.
        //
        Status = ZwWriteFile(
            hDstFile,
            NULL,
            NULL,
            NULL,
            &iost,
            DataBuffer,
            uLength,
            NULL,
            NULL);

        bRet = NT_SUCCESS(Status);

    } while (bCond);

    if (hSrcFile != NULL) ZwClose(hSrcFile);
    if (hDstFile != NULL) ZwClose(hDstFile);
    if (DataBuffer != NULL) ExFreePoolWithTag(DataBuffer, TAG_DRVMON_ENTRY);

    return bRet;
}

/*
* supInitializeHash
*
* Purpose:
*
* Initialize sha256 hash.
*
*/
VOID supInitializeHash(
    _Out_ PDM_HASH_CONTEXT Context
)
{
    sha256_starts((sha256_context *)Context);
}

/*
* supUpdateHash
*
* Purpose:
*
* Update sha256 hash.
*
*/
VOID supUpdateHash(
    _Inout_ PDM_HASH_CONTEXT Context,
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length
)
{
    sha256_update((sha256_context*)Context, (PUCHAR)Buffer, Length);
}

/*
* supFinalHash
*
* Purpose:
*
* Finalize sha256 hash.
*
*/
BOOLEAN supFinalHash(
    _Inout_ PDM_HASH_CONTEXT Context,
    _Out_writes_bytes_(HashLength) PVOID Hash,
    _In_ ULONG HashLength
)
{
    if (HashLength >= SHA256_DIGEST_LENGTH) {
        sha256_finish((sha256_context*)Context, (PUCHAR)Hash);
        return TRUE;
    }
    return FALSE;
}

/*
* supSha256Buffer
*
* Purpose:
*
* Calculate sha256 for given buffer.
*
*/
BOOLEAN supSha256Buffer(
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _Out_writes_bytes_(HashLength) PVOID Hash,
    _In_ ULONG HashLength
)
{
    DM_HASH_CONTEXT Context;

    supInitializeHash(&Context);
    supUpdateHash(&Context, Buffer, Length);
    return supFinalHash(&Context, Hash, HashLength);
}

/*
* supPrintHash
*
* Purpose:
*
* Output sha256 hash.
*
*/
_Success_(return == TRUE)
BOOLEAN supPrintHash(
    _In_reads_bytes_(HashLength) PUCHAR Hash,
    _In_ ULONG HashLength,
    _Out_writes_bytes_(OutputLength) PUCHAR Output,
    _In_ ULONG OutputLength
)
{
    unsigned int i;
    if ((OutputLength < SHA256_HASH_STRING_LENGTH) ||
        (HashLength != SHA256_DIGEST_LENGTH))
        return FALSE;

    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        Output[i * 2] = supConvertTableUpperCase[Hash[i] >> 4];
        Output[i * 2 + 1] = supConvertTableUpperCase[Hash[i] & 0xf];
    }
    return TRUE;
}

/*
* supHashFile
*
* Purpose:
*
* Calculate hash for given file.
*
*/
_Success_(return == TRUE)
BOOLEAN supHashFile(
    _In_ PUNICODE_STRING FileName,
    _Out_writes_bytes_(HashLength) PVOID Hash,
    _In_ ULONG HashLength,
    _In_ HASHCALLBACK HashCallback
)
{
    BOOLEAN bResult = FALSE, bCond = FALSE;
    NTSTATUS Status;
    ULONG FileSize;
    SIZE_T BufferSize;
    HANDLE hFile = NULL;
    PVOID FileBuffer = NULL;
    OBJECT_ATTRIBUTES Obja;
    IO_STATUS_BLOCK IoStatusBlock;

    //
    // Validate input parameters.
    //
    if (((HashLength > 0) && (Hash == NULL)) ||
        ((HashLength == 0) && (Hash != NULL)) ||
        (HashCallback == NULL) || (FileName == NULL))
    {
        return FALSE;
    }

    do {

        //
        // Open input file.
        //
        InitializeObjectAttributes(
            &Obja,
            FileName,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            NULL,
            NULL);

        Status = ZwOpenFile(
            &hFile,
            FILE_GENERIC_READ,
            &Obja,
            &IoStatusBlock,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);

        if (!NT_SUCCESS(Status))
            break;

        //
        // Query file size.
        //
        FileSize = 0;
        if (supGetFileSize(hFile, &FileSize, NULL) == FALSE)
            break;

        if (FileSize == 0)
            break;

        //
        // Allocate buffer for file.
        //
        BufferSize = align((ULONG_PTR)FileSize, PAGE_SIZE);
        FileBuffer = ExAllocatePoolWithTag(
            PagedPool,
            BufferSize,
            TAG_DRVMON_ENTRY);

        if (FileBuffer == NULL)
            break;

        //
        // Read file to buffer.
        //
        Status = ZwReadFile(
            hFile,
            NULL,
            NULL,
            NULL,
            &IoStatusBlock,
            FileBuffer,
            FileSize,
            NULL,
            NULL);

        if (!NT_SUCCESS(Status))
            break;

        //
        // Run callback to get hash.
        //
        bResult = HashCallback(
            FileBuffer,
            FileSize,
            Hash,
            HashLength);

    } while (bCond);

    if (hFile != NULL) ZwClose(hFile);
    if (FileBuffer != NULL) ExFreePoolWithTag(
        FileBuffer,
        TAG_DRVMON_ENTRY);

    return bResult;
}

/*
* supJustFileName
*
* Purpose:
*
* Return filename from path.
*
*/
wchar_t *supJustFileName(
    const wchar_t *f
)
{
    wchar_t *p = (wchar_t *)f;

    if (f == 0)
        return 0;

    while (*f != (wchar_t)0) {
        if (*f == (wchar_t)'\\')
            p = (wchar_t *)f + 1;
        f++;
    }
    return p;
}

/*
* supGetFileImageName
*
* Purpose:
*
* Query driver filename, check if it in symbolic link format.
*
*/
BOOLEAN supGetFileImageName(
    _In_ PUNICODE_STRING InputImageName,
    _Inout_ PUNICODE_STRING OutputImageName
)
{
    NTSTATUS Status;
    OBJECT_ATTRIBUTES objectAttributes;
    HANDLE LinkHandle;
    ULONG NumberOfChecks;
    BOOLEAN SymLinkProcessed = FALSE;

    if (
        (!ARGUMENT_PRESENT(InputImageName)) ||
        (!ARGUMENT_PRESENT(OutputImageName))
        )
    {
        return FALSE;
    }

    //
    // Test file path to be symbolic link.
    //
    InitializeObjectAttributes(
        &objectAttributes,
        InputImageName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        (HANDLE)NULL,
        (PSECURITY_DESCRIPTOR)NULL);

    LinkHandle = NULL;
    Status = ZwOpenSymbolicLinkObject(
        &LinkHandle,
        SYMBOLIC_LINK_QUERY,
        &objectAttributes);

    //
    // The given path is symbolic link.
    //
    if ((NT_SUCCESS(Status)) && (LinkHandle != NULL)) {

        SymLinkProcessed = FALSE;
        NumberOfChecks = 0;

        //
        // Handle case A->B->...->Z->mydriver.sys.
        //
        do {

            //
            // Query target of symbolic link, result will be stored in OutputImageName unicode string.
            //
            Status = ZwQuerySymbolicLinkObject(
                LinkHandle,
                OutputImageName,
                NULL);

            ZwClose(LinkHandle);
            LinkHandle = NULL;

            if (NT_SUCCESS(Status)) {

                //
                // Test if this is another symbolic link.
                //
                InitializeObjectAttributes(&objectAttributes,
                    OutputImageName,
                    OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                    (HANDLE)NULL,
                    (PSECURITY_DESCRIPTOR)NULL);

                Status = ZwOpenSymbolicLinkObject(
                    &LinkHandle,
                    SYMBOLIC_LINK_QUERY,
                    &objectAttributes);

                //
                // Not symbolic link, we are done.
                //
                if (!NT_SUCCESS(Status)) {
                    SymLinkProcessed = TRUE;
                    break;
                }
                //
                // Another symlink, do one more iteration. 
                // If NumberOfChecks exceed maximum allowed return error.
                //
                NumberOfChecks += 1;
                if (NumberOfChecks > 20) {
                    //
                    // Recursion is too long, abort.
                    //
                    SymLinkProcessed = FALSE;
                    break;
                }
            }
            else {
                //
                // Could not query symlink target, abort.
                //
                SymLinkProcessed = FALSE;
                break;
            }

        } while (SymLinkProcessed == FALSE);

        if (LinkHandle != NULL) ZwClose(LinkHandle);

        return SymLinkProcessed;

    }
    else {
        //
        // This is not symbolic link.
        //
        RtlCopyUnicodeString(OutputImageName, InputImageName);
        return TRUE;
    }
}

/*
* supIsNtNamePrefix
*
* Purpose:
*
* Return offset to Dos name in case if given lpName is Nt path name.
*
*/
USHORT supIsNtNamePrefix(
    _In_ LPWSTR lpName,
    _In_ SIZE_T cbName
)
{
    if ((cbName >= ObpDosDevicesShortName.Length) &&
        (*(PULONGLONG)(lpName) == ObpDosDevicesShortNamePrefix.Alignment.QuadPart)) {
        return ObpDosDevicesShortName.Length / sizeof(WCHAR);
    }
    return 0;
}
