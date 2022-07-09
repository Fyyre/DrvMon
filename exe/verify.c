/*******************************************************************************
*
*  (C) COPYRIGHT wj32 ProcessHacker, DrvMon (C) 2010 - 2017 EP_X0FF & Fyyre
*
*  TITLE:       VERIFY.C
*
*  VERSION:     3.00
*
*  DATE:        10 Apr 2017
*
*  This module based on Process Hacker verification code.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

#pragma comment(lib, "wintrust.lib")

static GUID WinTrustActionGenericVerifyV2 = WINTRUST_ACTION_GENERIC_VERIFY_V2;
static GUID DriverActionVerify = DRIVER_ACTION_VERIFY;

ptrCertFreeCertificateContext pCertFreeCertificateContext;
ptrCryptCATAdminCalcHashFromFileHandle pCryptCATAdminCalcHashFromFileHandle;
ptrCryptCATAdminAcquireContext pCryptCATAdminAcquireContext;
ptrCryptCATAdminReleaseContext pCryptCATAdminReleaseContext;
ptrCryptCATAdminEnumCatalogFromHash pCryptCATAdminEnumCatalogFromHash;
ptrCryptCATCatalogInfoFromContext pCryptCATCatalogInfoFromContext;
ptrCryptCATAdminReleaseCatalogContext pCryptCATAdminReleaseCatalogContext;
ptrWTHelperProvDataFromStateData pWTHelperProvDataFromStateData;
ptrWTHelperGetProvSignerFromChain pWTHelperGetProvSignerFromChain;
ptrCertDuplicateCertificateContext pCertDuplicateCertificateContext;

/*
* DmVerifyInit
*
* Purpose:
*
* Get required routine pointers.
*
*/
BOOLEAN DmVerifyInit(
    VOID
)
{
    HMODULE wintrust;
    HMODULE crypt32;

    wintrust = LoadLibrary(L"wintrust.dll");
    crypt32 = LoadLibrary(L"crypt32.dll");

    if ((wintrust == NULL) || (crypt32 == NULL))
        return FALSE;

    if (pCertFreeCertificateContext == NULL) {
        pCertFreeCertificateContext = (ptrCertFreeCertificateContext)GetProcAddress(crypt32, "CertFreeCertificateContext");
        if (pCertFreeCertificateContext == NULL) return FALSE;
    }

    if (pCertDuplicateCertificateContext == NULL) {
        pCertDuplicateCertificateContext = (ptrCertDuplicateCertificateContext)GetProcAddress(crypt32, "CertDuplicateCertificateContext");
        if (pCertDuplicateCertificateContext == NULL) return FALSE;
    }

    if (pCryptCATAdminCalcHashFromFileHandle == NULL) {
        pCryptCATAdminCalcHashFromFileHandle = (ptrCryptCATAdminCalcHashFromFileHandle)GetProcAddress(wintrust, "CryptCATAdminCalcHashFromFileHandle");
        if (pCryptCATAdminCalcHashFromFileHandle == NULL) return FALSE;
    }

    if (pCryptCATAdminAcquireContext == NULL) {
        pCryptCATAdminAcquireContext = (ptrCryptCATAdminAcquireContext)GetProcAddress(wintrust, "CryptCATAdminAcquireContext");
        if (pCryptCATAdminAcquireContext == NULL) return FALSE;
    }

    if (pCryptCATAdminReleaseContext == NULL) {
        pCryptCATAdminReleaseContext = (ptrCryptCATAdminReleaseContext)GetProcAddress(wintrust, "CryptCATAdminReleaseContext");
        if (pCryptCATAdminReleaseContext == NULL) return FALSE;
    }

    if (pCryptCATAdminEnumCatalogFromHash == NULL) {
        pCryptCATAdminEnumCatalogFromHash = (ptrCryptCATAdminEnumCatalogFromHash)GetProcAddress(wintrust, "CryptCATAdminEnumCatalogFromHash");
        if (pCryptCATAdminEnumCatalogFromHash == NULL) return FALSE;
    }

    if (pCryptCATCatalogInfoFromContext == NULL) {
        pCryptCATCatalogInfoFromContext = (ptrCryptCATCatalogInfoFromContext)GetProcAddress(wintrust, "CryptCATCatalogInfoFromContext");
        if (pCryptCATCatalogInfoFromContext == NULL) return FALSE;
    }

    if (pCryptCATAdminReleaseCatalogContext == NULL) {
        pCryptCATAdminReleaseCatalogContext = (ptrCryptCATAdminReleaseCatalogContext)GetProcAddress(wintrust, "CryptCATAdminReleaseCatalogContext");
        if (pCryptCATAdminReleaseCatalogContext == NULL) return FALSE;
    }

    if (pWTHelperProvDataFromStateData == NULL) {
        pWTHelperProvDataFromStateData = (ptrWTHelperProvDataFromStateData)GetProcAddress(wintrust, "WTHelperProvDataFromStateData");
        if (pWTHelperProvDataFromStateData == NULL) return FALSE;
    }

    if (pWTHelperGetProvSignerFromChain == NULL) {
        pWTHelperGetProvSignerFromChain = (ptrWTHelperGetProvSignerFromChain)GetProcAddress(wintrust, "WTHelperGetProvSignerFromChain");
        if (pWTHelperGetProvSignerFromChain == NULL) return FALSE;
    }

    return TRUE;
}

/*
* StatusToVerifyResult
*
* Purpose:
*
* Convert result from WinVerifyTrust to VERIFY_RESULT.
*
*/
VERIFY_RESULT StatusToVerifyResult(
    _In_ LONG Status
)
{
    switch (Status)
    {
    case 0:
        return VrTrusted;
    case TRUST_E_NOSIGNATURE:
        return VrNoSignature;
    case CERT_E_EXPIRED:
        return VrExpired;
    case CERT_E_REVOKED:
        return VrRevoked;
    case TRUST_E_EXPLICIT_DISTRUST:
        return VrDistrust;
    case CRYPT_E_SECURITY_SETTINGS:
        return VrSecuritySettings;
    case TRUST_E_BAD_DIGEST:
        return VrBadSignature;
    default:
        return VrSecuritySettings;
    }
}

/*
* FreeVerifySignatures
*
* Purpose:
*
* Release memory allocated for signatures.
*
*/
VOID FreeVerifySignatures(
    _In_ PCERT_CONTEXT *Signatures,
    _In_ ULONG NumberOfSignatures
)
{
    ULONG i;

    if (Signatures) {
        for (i = 0; i < NumberOfSignatures; i++) {
            pCertFreeCertificateContext((PCCERT_CONTEXT)Signatures[i]);
        }
        supHeapFree(Signatures);
    }
}

/*
* GetSignaturesFromStateData
*
* Purpose:
*
* Dump certificates info.
*
*/
BOOLEAN GetSignaturesFromStateData(
    _In_ HANDLE StateData,
    _Out_ PCERT_CONTEXT **Signatures,
    _Out_ PULONG NumberOfSignatures
)
{
    PCRYPT_PROVIDER_DATA provData;
    PCRYPT_PROVIDER_SGNR sgnr;
    PCERT_CONTEXT *signatures;
    ULONG i;
    ULONG numberOfSignatures;
    ULONG index;

    provData = pWTHelperProvDataFromStateData(StateData);

    if (!provData)
    {
        *Signatures = NULL;
        *NumberOfSignatures = 0;
        return FALSE;
    }

    i = 0;
    numberOfSignatures = 0;
    sgnr = NULL;

    do {
        sgnr = pWTHelperGetProvSignerFromChain(provData, i, FALSE, 0);
        if (sgnr) {
            if (sgnr->csCertChain != 0)
                numberOfSignatures++;

            i++;
        }

    } while (sgnr);


    if (numberOfSignatures != 0)
    {
        signatures = supHeapAlloc(numberOfSignatures * sizeof(PCERT_CONTEXT));
        i = 0;
        index = 0;
        sgnr = NULL;

        do {
            sgnr = pWTHelperGetProvSignerFromChain(provData, i, FALSE, 0);
            if (sgnr) {
                if (sgnr->csCertChain != 0)
                    signatures[index++] = (PCERT_CONTEXT)pCertDuplicateCertificateContext((PCCERT_CONTEXT)sgnr->pasCertChain[0].pCert);

                i++;
            }

        } while (sgnr);
    }
    else
    {
        signatures = NULL;
    }

    *Signatures = signatures;
    *NumberOfSignatures = numberOfSignatures;

    return TRUE;
}

/*
* VerifyFile
*
* Purpose:
*
* Wrapper for WinVerifyTrust call.
*
*/
VERIFY_RESULT VerifyFile(
    _In_ PVERIFY_OPTIONS VerifyOptions,
    _In_ ULONG UnionChoice,
    _In_ PVOID UnionData,
    _In_ GUID *ActionId,
    _In_opt_ PVOID PolicyCallbackData,
    _Out_ PCERT_CONTEXT **Signatures,
    _Out_ PULONG NumberOfSignatures
)
{
    LONG Status;
    WINTRUST_DATA TrustData;

    RtlSecureZeroMemory(&TrustData, sizeof(TrustData));

    TrustData.cbStruct = sizeof(WINTRUST_DATA);
    TrustData.pPolicyCallbackData = PolicyCallbackData;
    TrustData.dwUIChoice = WTD_UI_NONE;
    TrustData.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    TrustData.dwUnionChoice = UnionChoice;
    TrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    TrustData.dwProvFlags = WTD_SAFER_FLAG;
    TrustData.pFile = UnionData;

    if (UnionChoice == WTD_CHOICE_CATALOG)
        TrustData.pCatalog = UnionData;

    if (VerifyOptions->Flags & VERIFY_PREVENT_NETWORK_ACCESS) {
        TrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
        TrustData.dwProvFlags |= WTD_CACHE_ONLY_URL_RETRIEVAL;
    }

    Status = WinVerifyTrust(NULL, ActionId, &TrustData);
    GetSignaturesFromStateData(TrustData.hWVTStateData, Signatures, NumberOfSignatures);

    TrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, ActionId, &TrustData);

    return StatusToVerifyResult(Status);
}

/*
* CalculateFileHash
*
* Purpose:
*
* Calculate hash for file by given handle.
*
*/
_Success_(return != FALSE)
BOOLEAN CalculateFileHash(
    _In_ HANDLE FileHandle,
    _Out_ PUCHAR *FileHash,
    _Out_ PULONG FileHashLength,
    _Out_ HANDLE *CatAdminHandle
)
{
    HANDLE catAdminHandle;
    PUCHAR fileHash;
    ULONG fileHashLength;

    if (!pCryptCATAdminAcquireContext(&catAdminHandle, &DriverActionVerify, 0))
        return FALSE;

    fileHashLength = 32;
    fileHash = supHeapAlloc(fileHashLength);

    if (!pCryptCATAdminCalcHashFromFileHandle(FileHandle, &fileHashLength, fileHash, 0))
    {
        supHeapFree(fileHash);
        fileHash = supHeapAlloc(fileHashLength);

        if (!pCryptCATAdminCalcHashFromFileHandle(FileHandle, &fileHashLength, fileHash, 0))
        {
            pCryptCATAdminReleaseContext(catAdminHandle, 0);
            supHeapFree(fileHash);
            return FALSE;
        }
    }

    *FileHash = fileHash;
    *FileHashLength = fileHashLength;
    *CatAdminHandle = catAdminHandle;

    return TRUE;
}

/*
* VerifyFileFromCatalog
*
* Purpose:
*
* Verify file signature from windows catalog file or given catalog names.
*
*/
VERIFY_RESULT VerifyFileFromCatalog(
    _In_ PVERIFY_OPTIONS VerifyOptions,
    _In_ HANDLE FileHandle,
    _Out_ PCERT_CONTEXT **Signatures,
    _Out_ PULONG NumberOfSignatures
)
{
    VERIFY_RESULT verifyResult = VrNoSignature;
    CATALOG_INFO ci;
    DRIVER_VER_INFO verInfo;
    PCERT_CONTEXT *signatures;
    ULONG numberOfSignatures;
    WINTRUST_CATALOG_INFO catalogInfo;
    LARGE_INTEGER fileSize;
    ULONG fileSizeLimit;
    PUCHAR fileHash = NULL;
    ULONG fileHashLength = 0;
    LPWSTR fileHashTag = NULL;
    HANDLE catAdminHandle = NULL;
    HANDLE catInfoHandle = NULL;
    ULONG i;

    RtlSecureZeroMemory(&catalogInfo, sizeof(catalogInfo));

    *Signatures = NULL;
    *NumberOfSignatures = 0;

    if (!GetFileSizeEx(FileHandle, &fileSize))
        return VrNoSignature;

    signatures = NULL;
    numberOfSignatures = 0;

    if (VerifyOptions->FileSizeLimitForHash != (ULONG)-1) {
        fileSizeLimit = VERIFY_DEFAULT_SIZE_LIMIT;

        if (VerifyOptions->FileSizeLimitForHash != 0)
            fileSizeLimit = VerifyOptions->FileSizeLimitForHash;

        if (fileSize.QuadPart > fileSizeLimit)
            return VrNoSignature;
    }

    if (CalculateFileHash(FileHandle, &fileHash,
        &fileHashLength, &catAdminHandle))
    {
        fileHashTag = supPrintHashEx(fileHash, fileHashLength, FALSE);

        catInfoHandle = pCryptCATAdminEnumCatalogFromHash(
            catAdminHandle,
            fileHash,
            fileHashLength,
            0,
            NULL);

        if (catInfoHandle) {

            RtlSecureZeroMemory(&ci, sizeof(ci));
            RtlSecureZeroMemory(&verInfo, sizeof(verInfo));

            if (pCryptCATCatalogInfoFromContext(catInfoHandle, &ci, 0)) {

                verInfo.cbStruct = sizeof(DRIVER_VER_INFO);

                catalogInfo.cbStruct = sizeof(catalogInfo);
                catalogInfo.pcwszCatalogFilePath = ci.wszCatalogFile;
                catalogInfo.pcwszMemberFilePath = VerifyOptions->FileName;
                catalogInfo.pcwszMemberTag = fileHashTag;
                catalogInfo.pbCalculatedFileHash = fileHash;
                catalogInfo.cbCalculatedFileHash = fileHashLength;
                catalogInfo.hCatAdmin = catAdminHandle;

                verifyResult = VerifyFile(
                    VerifyOptions,
                    WTD_CHOICE_CATALOG,
                    &catalogInfo,
                    &DriverActionVerify,
                    &verInfo,
                    &signatures,
                    &numberOfSignatures);

                if (verInfo.pcSignerCertContext)
                    pCertFreeCertificateContext(verInfo.pcSignerCertContext);
            }

            pCryptCATAdminReleaseCatalogContext(catAdminHandle, catInfoHandle, 0);
        }
        else {

            for (i = 0; i < VerifyOptions->NumberOfCatalogFileNames; i++) {
                catalogInfo.cbStruct = sizeof(catalogInfo);
                catalogInfo.pcwszCatalogFilePath = (LPCWSTR)VerifyOptions->CatalogFileNames[i];
                catalogInfo.pcwszMemberFilePath = VerifyOptions->FileName;
                catalogInfo.pcwszMemberTag = fileHashTag;
                catalogInfo.pbCalculatedFileHash = fileHash;
                catalogInfo.cbCalculatedFileHash = fileHashLength;
                catalogInfo.hCatAdmin = catAdminHandle;
                verifyResult = VerifyFile(
                    VerifyOptions,
                    WTD_CHOICE_CATALOG,
                    &catalogInfo,
                    &WinTrustActionGenericVerifyV2,
                    NULL,
                    &signatures, &numberOfSignatures);

                if (verifyResult == VrTrusted)
                    break;

                if (signatures) {
                    FreeVerifySignatures(signatures, numberOfSignatures);
                }
            }
        }

        if (fileHash)
            supHeapFree(fileHash);

        pCryptCATAdminReleaseContext(catAdminHandle, 0);
    }


    if (fileHashTag)
        supHeapFree(fileHashTag);

    *Signatures = signatures;
    *NumberOfSignatures = numberOfSignatures;

    return verifyResult;
}

/*
* VerifyFileEx
*
* Purpose:
*
* Verify digital signature of file via embedded signature of catalog file.
*
*/
NTSTATUS VerifyFileEx(
    _In_ PVERIFY_OPTIONS VerifyOptions,
    _Out_ VERIFY_RESULT *VerifyResult,
    _Out_opt_ PCERT_CONTEXT **Signatures,
    _Out_opt_ PULONG NumberOfSignatures
)
{
    BOOL bCond = FALSE;
    NTSTATUS Status;
    HANDLE hFile;
    UNICODE_STRING usFileName;
    IO_STATUS_BLOCK IoStatusBlock;
    OBJECT_ATTRIBUTES Obja;
    WINTRUST_FILE_INFO FileInfo;
    VERIFY_RESULT vResult;
    PCERT_CONTEXT *signatures = NULL;
    ULONG numberOfSignatures = 0;

    if (Signatures)
        *Signatures = NULL;

    if (NumberOfSignatures)
        *NumberOfSignatures = 0;

    hFile = NULL;
    usFileName.Buffer = NULL;
    if (!RtlDosPathNameToNtPathName_U(VerifyOptions->FileName,
        &usFileName, NULL, NULL))
        return STATUS_UNSUCCESSFUL;

    do {
        InitializeObjectAttributes(&Obja, &usFileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

        Status = NtOpenFile(&hFile,
            FILE_GENERIC_READ,
            &Obja,
            &IoStatusBlock,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);

        if (!NT_SUCCESS(Status))
            break;

        RtlSecureZeroMemory(&FileInfo, sizeof(FileInfo));

        FileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
        FileInfo.pcwszFilePath = VerifyOptions->FileName;
        FileInfo.hFile = hFile;

        vResult = VerifyFile(
            VerifyOptions,
            WTD_CHOICE_FILE,
            &FileInfo,
            &WinTrustActionGenericVerifyV2,
            NULL,
            &signatures,
            &numberOfSignatures);

        if (vResult == VrNoSignature) {

            FreeVerifySignatures(signatures, numberOfSignatures);

            vResult = VerifyFileFromCatalog(
                VerifyOptions,
                hFile,
                &signatures,
                &numberOfSignatures);

        }

        *VerifyResult = vResult;

        if (Signatures)
            *Signatures = signatures;
        else
            FreeVerifySignatures(signatures, numberOfSignatures);

        if (NumberOfSignatures)
            *NumberOfSignatures = numberOfSignatures;

        Status = STATUS_SUCCESS;

    } while (bCond);

    if (hFile != NULL) NtClose(hFile);

    if (usFileName.Buffer)
        RtlFreeUnicodeString(&usFileName);

    return Status;
}

/*
* DmVerifyFile
*
* Purpose:
*
* Check digital signature for given file.
*
*/
VERIFY_RESULT DmVerifyFile(
    _In_ LPWSTR FileName
)
{
    NTSTATUS Status;
    VERIFY_OPTIONS VerifyOptions;
    VERIFY_RESULT verifyResult;
    PCERT_CONTEXT *signatures;
    ULONG numberOfSignatures;

    VerifyOptions.CatalogFileNames = NULL;
    VerifyOptions.FileName = FileName;
    VerifyOptions.Flags = VERIFY_PREVENT_NETWORK_ACCESS;
    VerifyOptions.NumberOfCatalogFileNames = 0;
    VerifyOptions.FileSizeLimitForHash = (ULONG)-1; //unlimited hash size

    if (!DmVerifyInit())
        return VrUnknown;

    Status = VerifyFileEx(&VerifyOptions,
        &verifyResult,
        &signatures,
        &numberOfSignatures);

    if (NT_SUCCESS(Status)) {
        FreeVerifySignatures(signatures, numberOfSignatures);
        return verifyResult;
    }
    else {
        return VrNoSignature;
    }
}

VOID DmxxxTestVerify(
    VOID
)
{
    VERIFY_RESULT vr;

    vr = DmVerifyFile(L"C:\\malware\\inetmgr15063.xe");

    if (vr == VrNoSignature)
        OutputDebugString(L"No signature");
    if (vr == VrBadSignature)
        OutputDebugString(L"Bad");
    if (vr == VrTrusted)
        OutputDebugString(L"Trusted");
    if (vr == VrExpired)
        OutputDebugString(L"Expired");
    if (vr == VrRevoked)
        OutputDebugString(L"Revoked");
    if (vr == VrDistrust)
        OutputDebugString(L"Distrusted");

}
