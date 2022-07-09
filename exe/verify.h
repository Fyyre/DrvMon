/*******************************************************************************
*
*  (C) COPYRIGHT wj32 ProcessHacker, DrvMon (C) 2010 - 2017 EP_X0FF & Fyyre
*
*  TITLE:       VERIFY.H
*
*  VERSION:     3.00
*
*  DATE:        10 Apr 2017
*
*  Digital certificate verification header file.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

#include <Softpub.h>
#include <mscat.h>

typedef enum _VERIFY_RESULT {
    VrUnknown = 0,
    VrNoSignature,
    VrTrusted,
    VrExpired,
    VrRevoked,
    VrDistrust,
    VrSecuritySettings,
    VrBadSignature
} VERIFY_RESULT, *PVERIFY_RESULT;

typedef struct _VERIFY_OPTIONS {
    LPWSTR FileName;
    ULONG Flags;
    ULONG FileSizeLimitForHash;
    ULONG NumberOfCatalogFileNames;
    PWSTR *CatalogFileNames;
} VERIFY_OPTIONS, *PVERIFY_OPTIONS;

#define VERIFY_PREVENT_NETWORK_ACCESS 0x1

#define VERIFY_DEFAULT_SIZE_LIMIT (32 * 1024 * 1024)


typedef BOOL(WINAPI *ptrCertFreeCertificateContext)(
    _In_ PCCERT_CONTEXT pCertContext);

typedef PCCERT_CONTEXT(WINAPI *ptrCertDuplicateCertificateContext)(
    _In_ PCCERT_CONTEXT pCertContext);

typedef BOOL(WINAPI *ptrCryptCATAdminCalcHashFromFileHandle)(
    HANDLE hFile,
    DWORD *pcbHash,
    BYTE *pbHash,
    DWORD dwFlags);

typedef BOOL(WINAPI *ptrCryptCATAdminAcquireContext)(
    HANDLE *phCatAdmin,
    GUID *pgSubsystem,
    DWORD dwFlags);

typedef BOOL(WINAPI *ptrCryptCATAdminReleaseContext)(
    HANDLE hCatAdmin,
    DWORD dwFlags);

typedef HANDLE(WINAPI *ptrCryptCATAdminEnumCatalogFromHash)(
    HANDLE hCatAdmin,
    BYTE *pbHash,
    DWORD cbHash,
    DWORD dwFlags,
    HANDLE *phPrevCatInfo);

typedef BOOL(WINAPI *ptrCryptCATCatalogInfoFromContext)(
    HANDLE hCatInfo,
    CATALOG_INFO *psCatInfo,
    DWORD dwFlags);

typedef BOOL(WINAPI *ptrCryptCATAdminReleaseCatalogContext)(
    HANDLE hCatAdmin,
    HANDLE hCatInfo,
    DWORD dwFlags);

typedef PCRYPT_PROVIDER_DATA(WINAPI *ptrWTHelperProvDataFromStateData)(
    HANDLE hStateData);

typedef PCRYPT_PROVIDER_SGNR(WINAPI *ptrWTHelperGetProvSignerFromChain)(
    CRYPT_PROVIDER_DATA *pProvData,
    DWORD idxSigner,
    BOOL fCounterSigner,
    DWORD idxCounterSigner);

VERIFY_RESULT DmVerifyFile(
    _In_ LPWSTR FileName);

VOID DmxxxTestVerify(
    VOID);
