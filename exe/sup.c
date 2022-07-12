/*******************************************************************************
*
*  (C) COPYRIGHT Fyyre & EP_X0FF, 2010 - 2018
*
*  TITLE:       SUP.C
*
*  VERSION:     3.01
*
*  DATE:        10 Nov 2017
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

CHAR supConvertTableUpperCase[] =
"0123456789" /* 0 - 9 */
"ABCDEFGHIJKLMNOPQRSTUVWXYZ" /* 10 - 35 */
" !\"#$%&'()*+,-./" /* 36 - 51 */
":;<=>?@" /* 52 - 58 */
"[\\]^_`" /* 59 - 64 */
"{|}~" /* 65 - 68 */
;

CHAR supConvertTableLowerCase[] =
"0123456789" /* 0 - 9 */
"abcdefghijklmnopqrstuvwxyz" /* 10 - 35 */
" !\"#$%&'()*+,-./" /* 36 - 51 */
":;<=>?@" /* 52 - 58 */
"[\\]^_`" /* 59 - 64 */
"{|}~" /* 65 - 68 */
;

pfnHtmlHelpW pHtmlHelpW;

const ALIGNEDNAME ObpDosDevicesShortNamePrefix = { L'\\',L'?',L'?',L'\\' }; // L"\??\"
const UNICODE_STRING ObpDosDevicesShortName = {
    sizeof(ObpDosDevicesShortNamePrefix),
    sizeof(ObpDosDevicesShortNamePrefix),
    (PWSTR)&ObpDosDevicesShortNamePrefix
};

/*
* supSetWaitCursor
*
* Purpose:
*
* Sets cursor state.
*
*/
VOID supSetWaitCursor(
    _In_ BOOL fSet
)
{
    ShowCursor(fSet);
    SetCursor(LoadCursor(NULL, fSet ? IDC_WAIT : IDC_ARROW));
}

/*
* supSetMenuIcon
*
* Purpose:
*
* Associates icon data with given menu item.
*
*/
VOID supSetMenuIcon(
    _In_ HMENU hMenu,
    _In_ UINT Item,
    _In_ ULONG_PTR IconData
)
{
    MENUITEMINFOW mii;
    RtlSecureZeroMemory(&mii, sizeof(mii));
    mii.cbSize = sizeof(mii);
    mii.fMask = MIIM_BITMAP | MIIM_DATA;
    mii.hbmpItem = HBMMENU_CALLBACK;
    mii.dwItemData = IconData;
    SetMenuItemInfo(hMenu, Item, FALSE, &mii);
}

/*
* supCenterWindow
*
* Purpose:
*
* Centers given window relative to it parent window.
*
*/
VOID supCenterWindow(
    _In_ HWND hwnd
)
{
    RECT rc, rcDlg, rcOwner;
    HWND hwndParent = GetParent(hwnd);

    //center window
    if (hwndParent) {
        GetWindowRect(hwndParent, &rcOwner);
        GetWindowRect(hwnd, &rcDlg);
        CopyRect(&rc, &rcOwner);
        OffsetRect(&rcDlg, -rcDlg.left, -rcDlg.top);
        OffsetRect(&rc, -rc.left, -rc.top);
        OffsetRect(&rc, -rcDlg.right, -rcDlg.bottom);
        SetWindowPos(hwnd,
            HWND_TOP,
            rcOwner.left + (rc.right / 2),
            rcOwner.top + (rc.bottom / 2),
            0, 0,
            SWP_NOSIZE);
    }
}

/*
* supReadFileToBuffer
*
* Purpose:
*
* Read file to buffer. Release memory when it no longer needed.
*
*/
PBYTE supReadFileToBuffer(
    _In_ LPWSTR lpFileName,
    _Inout_opt_ LPDWORD lpBufferSize
)
{
    BOOL        bCond = FALSE;
    NTSTATUS    status;
    HANDLE      hFile = NULL, hRoot = NULL;
    PBYTE       Buffer = NULL;
    SIZE_T      sz = 0;

    UNICODE_STRING              usName;
    OBJECT_ATTRIBUTES           attr;
    IO_STATUS_BLOCK             iost;
    FILE_STANDARD_INFORMATION   fi;

    do {

        RtlSecureZeroMemory(&usName, sizeof(usName));

        if (lpFileName == NULL)
            return NULL;

        if (!RtlDosPathNameToNtPathName_U(
            NtCurrentPeb()->ProcessParameters->CurrentDirectory.DosPath.Buffer, &usName, NULL, NULL))
        {
            break;
        }

        InitializeObjectAttributes(&attr, &usName, OBJ_CASE_INSENSITIVE, 0, NULL);
        status = NtCreateFile(&hRoot, FILE_LIST_DIRECTORY | SYNCHRONIZE,
            &attr,
            &iost,
            NULL,
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            NULL,
            0
        );

        RtlFreeUnicodeString(&usName);

        if (!NT_SUCCESS(status))
            break;

        RtlInitUnicodeString(&usName, lpFileName);
        InitializeObjectAttributes(&attr, &usName, OBJ_CASE_INSENSITIVE, hRoot, NULL);

        status = NtCreateFile(&hFile,
            FILE_READ_DATA | SYNCHRONIZE,
            &attr,
            &iost,
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            NULL,
            0
        );

        if (!NT_SUCCESS(status))
            break;

        RtlSecureZeroMemory(&fi, sizeof(fi));
        status = NtQueryInformationFile(hFile, &iost, &fi, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
        if (!NT_SUCCESS(status))
            break;

        sz = (SIZE_T)fi.EndOfFile.LowPart;
        status = NtAllocateVirtualMemory(NtCurrentProcess(), &Buffer, 0, &sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (NT_SUCCESS(status)) {

            status = NtReadFile(hFile, NULL, NULL, NULL, &iost, Buffer, fi.EndOfFile.LowPart, NULL, NULL);
            if (NT_SUCCESS(status)) {
                if (lpBufferSize)
                    *lpBufferSize = fi.EndOfFile.LowPart;
            }
            else {
                sz = 0;
                NtFreeVirtualMemory(NtCurrentProcess(), &Buffer, &sz, MEM_RELEASE);
                Buffer = NULL;
            }
        }

    } while (bCond);

    if (hRoot != NULL) {
        NtClose(hRoot);
    }

    if (hFile != NULL) {
        NtClose(hFile);
    }

    return Buffer;
}

/*
* supLdrQueryResourceData
*
* Purpose:
*
* Load resource by given id (win32 FindResource, SizeofResource, LockResource).
*
*/
PBYTE supLdrQueryResourceData(
    _In_ ULONG_PTR ResourceId,
    _In_ PVOID DllHandle,
    _In_ PULONG DataSize
)
{
    NTSTATUS                   status;
    ULONG_PTR                  IdPath[3];
    IMAGE_RESOURCE_DATA_ENTRY  *DataEntry;
    PBYTE                      Data = NULL;
    ULONG                      SizeOfData = 0;

    if (DllHandle != NULL) {

        IdPath[0] = (ULONG_PTR)RT_RCDATA; //type
        IdPath[1] = ResourceId;           //id
        IdPath[2] = 0;                    //lang

        status = LdrFindResource_U(DllHandle, (ULONG_PTR*)&IdPath, 3, &DataEntry);
        if (NT_SUCCESS(status)) {
            status = LdrAccessResource(DllHandle, DataEntry, &Data, &SizeOfData);
            if (NT_SUCCESS(status)) {
                if (DataSize) {
                    *DataSize = SizeOfData;
                }
            }
        }
    }
    return Data;
}

/*
* supOpenDrvMon
*
* Purpose:
*
* open DRVMON device.
*
*/
HANDLE supOpenDrvMon(
    _In_ LPWSTR lpDriverDevice,
    _Out_opt_ NTSTATUS *OutStatus
)
{
    HANDLE hDevice = NULL;
    NTSTATUS Status;
    OBJECT_ATTRIBUTES Obja;
    IO_STATUS_BLOCK IoStatusBlock;
    UNICODE_STRING usDrv;

    usDrv.Buffer = NULL;
    usDrv.Length = 0;
    usDrv.MaximumLength = 0;
    RtlInitUnicodeString(&usDrv, lpDriverDevice);
    InitializeObjectAttributes(&Obja, &usDrv, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtCreateFile(
        &hDevice,
        GENERIC_READ | GENERIC_WRITE,
        &Obja,
        &IoStatusBlock,
        NULL,
        0,
        0,
        FILE_OPEN,
        0,
        NULL,
        0);

    if (OutStatus)
        *OutStatus = Status;

    return hDevice;
}

/*
* supExtractDriver
*
* Purpose:
*
* Extract DRVMON from application resource.
*
*/
DWORD supExtractDriver(
    _In_ LPCWSTR lpExtractTo
)
{
    BOOL        bCond = FALSE;
    DWORD       dwResult = ERROR_BAD_DRIVER;
    HANDLE      hFile = INVALID_HANDLE_VALUE;
    ULONG       DataSize = 0, bytesIO = 0;

    PVOID       Resource;

    do {

        //
        // Query driver from resource.
        //
        Resource = supLdrQueryResourceData(
            IDR_DRVMON,
            g_ctx.hInstance,
            &DataSize);

        if (Resource == NULL)
            return ERROR_RESOURCE_NAME_NOT_FOUND;

        hFile = CreateFile(lpExtractTo, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            if (WriteFile(hFile, Resource, DataSize, &bytesIO, NULL) == FALSE)
                dwResult = GetLastError();
            else {
                if (DataSize == bytesIO)
                    dwResult = ERROR_SUCCESS;
                else
                    dwResult = ERROR_PARTIAL_COPY;
            }
            CloseHandle(hFile);
        }
        else
            dwResult = GetLastError();

    } while (bCond);
    return dwResult;
}

/*
* supHeapAlloc
*
* Purpose:
*
* Wrapper for RtlAllocateHeap with ucmHeap.
*
*/
PVOID supHeapAlloc(
    _In_ SIZE_T Size)
{
    return RtlAllocateHeap(g_ctx.dmHeap, HEAP_ZERO_MEMORY, Size);
}

/*
* supHeapFree
*
* Purpose:
*
* Wrapper for RtlFreeHeap with ucmHeap.
*
*/
BOOL supHeapFree(
    _In_ PVOID Memory)
{
    return RtlFreeHeap(g_ctx.dmHeap, 0, Memory);
}

/*
* DmSetOutputDirectory
*
* Purpose:
*
* Call driver to set new output directory.
*
*/
BOOL DmSetOutputDirectory(
    _In_ UNICODE_STRING *usOutputDirectory
)
{
    BOOL bResult;
    DWORD bytesIO = 0;
    DM_SET_OUTDIR SetOutDir;

    RtlSecureZeroMemory(&SetOutDir, sizeof(DM_SET_OUTDIR));
    SetOutDir.cb = sizeof(DM_SET_OUTDIR);

    __try {

        bResult = RtlDosPathNameToNtPathName_U(
            usOutputDirectory->Buffer,
            &SetOutDir.usOutputDirectory,
            NULL,
            NULL);

        if ((bResult == FALSE) ||
            (SetOutDir.usOutputDirectory.Length >= sizeof(g_szOutputDirectory)))
            __leave;

        bResult = DeviceIoControl(
            g_ctx.hDrvMonDevice,
            IOCTL_DRVMON_SETOUTPUT_DIRECTORY,
            &SetOutDir,
            sizeof(DM_SET_OUTDIR),
            NULL,
            0,
            &bytesIO,
            NULL);
    }
    __finally {
        if (SetOutDir.usOutputDirectory.Buffer)
            RtlFreeUnicodeString(&SetOutDir.usOutputDirectory);
    }

    return bResult;
}

/*
* DmSetInternalFlags
*
* Purpose:
*
* Call driver to set internal driver flags.
*
*/
BOOL DmSetInternalFlags(
    _In_ ULONG Flags
)
{
    DWORD bytesIO = 0;
    DM_SET_FLAG SetFlags;

    SetFlags.cb = sizeof(DM_SET_FLAG);
    SetFlags.DrvMonFlag = Flags;

    return DeviceIoControl(
        g_ctx.hDrvMonDevice,
        IOCTL_DRVMON_SET_FLAGS,
        &SetFlags,
        sizeof(DM_SET_FLAG),
        NULL,
        0,
        &bytesIO,
        NULL);
}

/*
* DmManageWhiteList
*
* Purpose:
*
* Call driver to add or remove entry from whitelist.
*
*/
BOOL DmManageWhiteList(
    _In_ BOOLEAN AddEntry,
    _In_ ULONG_PTR Tag,
    _In_ ULONG_PTR Flags,
    _In_reads_bytes_opt_(DriverNameLength) LPWSTR DriverName,
    _In_opt_ SIZE_T DriverNameLength,
    _In_reads_bytes_(HashLength) PUCHAR Hash,
    _In_ ULONG HashLength
)
{
    DWORD bytesIO = 0, IoControlCode;
    DM_WL_PACKET Packet;

    RtlSecureZeroMemory(&Packet, sizeof(DM_WL_PACKET));
    Packet.cb = sizeof(DM_WL_PACKET);

    Packet.Tag = Tag;
    Packet.Flags = Flags;

    if ((DriverNameLength > MAX_PATH) ||
        (HashLength > SHA256_DIGEST_LENGTH))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (DriverName) {
        _strcpy(Packet.DriverName, DriverName);
    }
    RtlCopyMemory(Packet.Hash, Hash, HashLength);

    if (AddEntry) {
        IoControlCode = IOCTL_DRVMON_ADDWLENTRY;
    }
    else {
        IoControlCode = IOCTL_DRVMON_REMOVEWLENTRY;
    }

    return DeviceIoControl(
        g_ctx.hDrvMonDevice,
        IoControlCode,
        &Packet,
        sizeof(DM_WL_PACKET),
        NULL,
        0,
        &bytesIO,
        NULL);
}


/*
* supOpenDialogExecute
*
* Purpose:
*
* Open dialog.
*
*/
BOOL supOpenDialogExecute(
    _In_ HWND OwnerWindow,
    _Inout_ LPWSTR OpenFileName,
    _In_ LPWSTR lpDialogFilter
)
{
    OPENFILENAME ofn;

    RtlSecureZeroMemory(&ofn, sizeof(OPENFILENAME));

    ofn.lStructSize = sizeof(OPENFILENAME);
    ofn.hwndOwner = OwnerWindow;
    ofn.lpstrFilter = lpDialogFilter;
    ofn.lpstrFile = OpenFileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_EXPLORER | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY | OFN_FILEMUSTEXIST;

    return GetOpenFileName(&ofn);
}

/*
* supSaveDialogExecute
*
* Purpose:
*
* Save dialog.
*
*/
BOOL supSaveDialogExecute(
    _In_ HWND OwnerWindow,
    _Inout_ LPWSTR SaveFileName,
    _In_ LPWSTR lpDialogFilter,
    _In_opt_ LPWSTR lpstrDefExt
)
{
    OPENFILENAME sfn;

    RtlSecureZeroMemory(&sfn, sizeof(OPENFILENAME));

    sfn.lStructSize = sizeof(OPENFILENAME);
    sfn.hwndOwner = OwnerWindow;
    sfn.lpstrFilter = lpDialogFilter;
    sfn.lpstrFile = SaveFileName;
    sfn.nMaxFile = MAX_PATH;
    sfn.lpstrDefExt = lpstrDefExt;
    sfn.Flags = OFN_EXPLORER | OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT;

    return GetSaveFileName(&sfn);
}

/*
* supSelectDirectory
*
* Purpose:
*
* Browse for folder dialog.
*
*/
BOOL supSelectDirectory(
    _In_ HWND hwnd,
    _In_ LPWSTR lpCaption,
    _Inout_ LPWSTR lpDirectory,
    _In_ SIZE_T cchDirectory
)
{
    BOOL bResult = FALSE;
    LPWSTR lpBuffer;
    BROWSEINFO BrowseInfo;
    ITEMIDLIST *ItemIDList = NULL;

    //X:\ + 0
    if ((cchDirectory == 0) || (cchDirectory < 4))
        return FALSE;

    lpBuffer = supHeapAlloc((1 + cchDirectory) * sizeof(WCHAR));
    if (lpBuffer == NULL)
        return FALSE;

    RtlSecureZeroMemory(&BrowseInfo, sizeof(BROWSEINFO));

    BrowseInfo.hwndOwner = hwnd;
    BrowseInfo.pszDisplayName = lpBuffer;
    BrowseInfo.lpszTitle = lpCaption;
    BrowseInfo.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE | BIF_DONTGOBELOWDOMAIN;

    ItemIDList = (ITEMIDLIST *)SHBrowseForFolder(&BrowseInfo);
    if (ItemIDList) {
        if (SHGetPathFromIDList(ItemIDList, lpBuffer)) {

            _strncpy(
                lpDirectory,
                cchDirectory,
                lpBuffer,
                cchDirectory);

            bResult = TRUE;
        }
        LocalFree(ItemIDList);
    }

    supHeapFree(lpBuffer);
    return bResult;
}

/*
* supCreateToolbarButtons
*
* Purpose:
*
* Main window toolbar initialization.
*
*/
VOID supCreateToolbarButtons(
    _In_ HWND hWndToolbar,
    _In_ HIMAGELIST hImageList
)
{
    INT ImageListID = 0, i = 0;
    TBBUTTON tbButtons[8];

    RtlSecureZeroMemory(tbButtons, sizeof(tbButtons));

    //separator
    tbButtons[i].fsStyle = BTNS_SEP;
    tbButtons[i].iBitmap = 10;

    //save output to disk
    tbButtons[++i].iBitmap = MAKELONG(IDX_SAVEBUTTON, ImageListID);;
    tbButtons[i].fsStyle = BTNS_BUTTON;
    tbButtons[i].idCommand = ID_FILE_SAVELOG;
    tbButtons[i].fsState = TBSTATE_ENABLED;

    //separator
    tbButtons[++i].fsStyle = BTNS_SEP;
    tbButtons[i].iBitmap = 10;

    //stop monitoring drivers
    tbButtons[++i].iBitmap = MAKELONG(IDX_CAPTUREBUTTON_ENABLE, ImageListID);;
    tbButtons[i].fsStyle = BTNS_BUTTON;
    tbButtons[i].idCommand = ID_MONITOR_CAPTUREDRIVERS;
    tbButtons[i].fsState = TBSTATE_ENABLED;

    //clean output
    tbButtons[++i].iBitmap = MAKELONG(IDX_CLEANBUTTON, ImageListID);
    tbButtons[i].fsStyle = BTNS_BUTTON;
    tbButtons[i].idCommand = ID_FILE_CLEARLOG;
    tbButtons[i].fsState = TBSTATE_ENABLED;

    //separator
    tbButtons[++i].fsStyle = BTNS_SEP;
    tbButtons[i].iBitmap = 10;

    //enable/disable drivers loading
    tbButtons[++i].iBitmap = MAKELONG(IDX_BLOCKBUTTON_ENABLE, ImageListID);
    tbButtons[i].fsStyle = BTNS_BUTTON;
    tbButtons[i].idCommand = ID_MONITOR_BLOCKDRIVERLOADING;
    tbButtons[i].fsState = TBSTATE_ENABLED;

    //autoscroll
    tbButtons[++i].iBitmap = MAKELONG(IDX_AUTOSCROLLBUTTON_ENABLE, ImageListID);
    tbButtons[i].fsStyle = BTNS_BUTTON;
    tbButtons[i].idCommand = ID_MONITOR_AUTOSCROLL;
    tbButtons[i].fsState = TBSTATE_ENABLED;

    SendMessage(hWndToolbar, TB_SETIMAGELIST, 0, (LPARAM)hImageList);
    SendMessage(hWndToolbar, TB_LOADIMAGES, (WPARAM)IDB_STD_SMALL_COLOR, (LPARAM)HINST_COMMCTRL);

    SendMessage(hWndToolbar, TB_BUTTONSTRUCTSIZE,
        (WPARAM)sizeof(TBBUTTON), 0);
    SendMessage(hWndToolbar, TB_ADDBUTTONS, (WPARAM)i + 1,
        (LPARAM)&tbButtons);

    SendMessage(hWndToolbar, TB_AUTOSIZE, 0, 0);
}

/*
* supIsNtNamePrefix
*
* Purpose:
*
* Return offset to Dos name in case if given lpName is Nt path name.
*
*/
UINT supIsNtNamePrefix(
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

/*
* supShowHelp
*
* Purpose:
*
* Display help file if available.
*
*/
VOID supShowHelp(
    VOID
)
{
    DWORD   dwSize;
    HKEY    hKey;
    LRESULT lRet;
    HANDLE  hHtmlOcx;
    WCHAR   szOcxPath[MAX_PATH + 1];
    WCHAR   szHelpFile[MAX_PATH * 2];

    RtlSecureZeroMemory(&szOcxPath, sizeof(szOcxPath));
    RtlSecureZeroMemory(szHelpFile, sizeof(szHelpFile));
    lRet = RegOpenKeyEx(HKEY_CLASSES_ROOT, HHCTRLOCXKEY, 0, KEY_QUERY_VALUE, &hKey);
    if (lRet == ERROR_SUCCESS) {
        dwSize = MAX_PATH * sizeof(WCHAR);
        lRet = RegQueryValueEx(hKey, L"", NULL, NULL, (LPBYTE)szHelpFile, &dwSize);
        RegCloseKey(hKey);

        if (lRet == ERROR_SUCCESS) {
            if (ExpandEnvironmentStrings(szHelpFile, szOcxPath, MAX_PATH) == 0) {
                lRet = ERROR_SECRET_TOO_LONG;
            }
        }
    }
    if (lRet != ERROR_SUCCESS) {
        _strcpy(szOcxPath, HHCTRLOCX);
    }

    RtlSecureZeroMemory(szHelpFile, sizeof(szHelpFile));
    if (!GetCurrentDirectory(MAX_PATH, szHelpFile)) {
        return;
    }
    _strcat(szHelpFile, DM_HELPFILE);

    hHtmlOcx = GetModuleHandle(HHCTRLOCX);
    if (hHtmlOcx == NULL) {
        hHtmlOcx = LoadLibrary(szOcxPath);
        if (hHtmlOcx == NULL) {
            return;
        }
    }
    if (pHtmlHelpW == NULL) {
        pHtmlHelpW = (pfnHtmlHelpW)GetProcAddress(hHtmlOcx, MAKEINTRESOURCEA(0xF));
        if (pHtmlHelpW == NULL) {
            return;
        }
    }
    pHtmlHelpW(GetDesktopWindow(), szHelpFile, 0, 0);
}

/*
* supConvertFileName
*
* Purpose:
*
* Translate Nt path name to Dos path name.
*
*/
BOOL supConvertFileName(
    _In_ LPWSTR NtFileName,
    _In_ SIZE_T ccNtFileName,
    _In_ LPWSTR DosFileName,
    _In_ SIZE_T ccDosFileName
)
{
    BOOL    bResult = FALSE, bFound = FALSE;
    WCHAR   szDrive[3];
    WCHAR   szName[MAX_PATH]; //for the device partition name
    WCHAR   szTemp[MAX_PATH * 2]; //for the disk array
    UINT    uNameLen = 0, i;
    WCHAR  *p = szTemp;
    SIZE_T  l = 0;

    if ((NtFileName == NULL) || (DosFileName == NULL) || (ccDosFileName < 4))
        return bResult;

    if (ccDosFileName < ccNtFileName)
        return bResult;

    i = supIsNtNamePrefix(NtFileName, ccNtFileName);
    if (i != 0) {
        _strncpy(DosFileName, ccDosFileName, NtFileName, ccNtFileName);
        return TRUE;
    }

    _strcpy(szDrive, TEXT(" :"));
    RtlSecureZeroMemory(szTemp, sizeof(szTemp));
    if (GetLogicalDriveStrings((MAX_PATH * 2) - 1, szTemp)) {
        do {
            *szDrive = *p;
            RtlSecureZeroMemory(szName, sizeof(szName));
            if (QueryDosDevice(szDrive, szName, MAX_PATH)) {
                uNameLen = (UINT)_strlen(szName);
                if (uNameLen < MAX_PATH) {
                    bFound = (_strncmp(NtFileName, szName, uNameLen) == 0);
                    if (bFound && *(NtFileName + uNameLen) == TEXT('\\')) {

                        _strcpy(DosFileName, szDrive);
                        l = _strlen(DosFileName);
                        _strncpy(&DosFileName[l], ccDosFileName - l, NtFileName + uNameLen, ccNtFileName - uNameLen);

                        bResult = TRUE;
                        break;
                    }
                }
            }
            while (*p++);
        } while (!bFound && *p); // end of string
    }
    return bResult;
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
    _In_ ULONG OutputLength,
    _In_ BOOLEAN LowerCase
)
{
    unsigned int i;
    CHAR *Table;

    if ((OutputLength < SHA256_HASH_STRING_LENGTH) ||
        (HashLength != SHA256_DIGEST_LENGTH))
        return FALSE;

    if (LowerCase)
        Table = supConvertTableLowerCase;
    else
        Table = supConvertTableUpperCase;

    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        Output[i * 2] = Table[Hash[i] >> 4];
        Output[i * 2 + 1] = Table[Hash[i] & 0xf];
    }
    return TRUE;
}

/*
* supPrintHashEx
*
* Purpose:
*
* Output hash.
* Returned buffer must be freed with supHeapFree when no longer needed.
*
*/
LPWSTR supPrintHashEx(
    _In_reads_bytes_(Length) PUCHAR Buffer,
    _In_ ULONG Length,
    _In_ BOOLEAN LowerCase
)
{
    unsigned int i;
    CHAR *Table;
    LPWSTR OutputString;

    if (LowerCase)
        Table = supConvertTableLowerCase;
    else
        Table = supConvertTableUpperCase;

    OutputString = supHeapAlloc((SIZE_T)(Length * 2 * sizeof(WCHAR)));
    if (OutputString == NULL) return NULL;

    for (i = 0; i < Length; i++) {
        OutputString[i * 2] = Table[Buffer[i] >> 4];
        OutputString[i * 2 + 1] = Table[Buffer[i] & 0xf];
    }

    return OutputString;
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
    _In_ LPWSTR lpFileName,
    _Out_writes_bytes_(HashLength) PVOID Hash,
    _In_ ULONG HashLength,
    _In_ HASHCALLBACK HashCallback
)
{
    BOOLEAN bResult;
    HANDLE hFile = NULL;
    HANDLE hEvent = NULL;
    PVOID FileBuffer = NULL;
    NTSTATUS Status;
    FILE_STANDARD_INFORMATION fsi;
    UNICODE_STRING NtFileName;
    OBJECT_ATTRIBUTES Obja;
    IO_STATUS_BLOCK IoStatusBlock;

    //
    // Validate input parameters.
    //
    if (((HashLength > 0) && (Hash == NULL)) ||
        ((HashLength == 0) && (Hash != NULL)) ||
        (HashCallback == NULL))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    NtFileName.Buffer = NULL;
    NtFileName.Length = 0;
    NtFileName.MaximumLength = 0;

    __try {

        //
        // Convert filepath to NT path format.
        //
        bResult = RtlDosPathNameToNtPathName_U(
            lpFileName,
            &NtFileName,
            NULL,
            NULL);

        if (bResult == FALSE) {
            Status = STATUS_INVALID_PARAMETER_1;
            __leave;
        }

        InitializeObjectAttributes(&Obja, &NtFileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

        //
        // Open file.
        //
        Status = NtOpenFile(
            &hFile,
            FILE_GENERIC_READ,
            &Obja,
            &IoStatusBlock,
            FILE_SHARE_READ,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);

        if (!NT_SUCCESS(Status))
            __leave;

        //
        // Create notification event for read.
        //
        Status = NtCreateEvent(
            &hEvent,
            EVENT_ALL_ACCESS,
            NULL,
            NotificationEvent,
            FALSE);

        if (!NT_SUCCESS(Status))
            __leave;

        //
        // Query file size. If file has zero size then exit.
        //
        RtlSecureZeroMemory(&fsi, sizeof(fsi));
        Status = NtQueryInformationFile(
            hFile,
            &IoStatusBlock,
            &fsi,
            sizeof(FILE_STANDARD_INFORMATION),
            FileStandardInformation);

        if (!NT_SUCCESS(Status))
            __leave;

        if (fsi.EndOfFile.LowPart == 0) {
            Status = STATUS_FILE_INVALID;
            __leave;
        }

        //
        // Allocate buffer.
        //
        FileBuffer = supHeapAlloc((SIZE_T)fsi.EndOfFile.LowPart);
        if (FileBuffer == NULL) {
            Status = STATUS_NO_MEMORY;
            __leave;
        }

        //
        // Read file.
        //
        Status = NtReadFile(
            hFile,
            hEvent,
            NULL,
            NULL,
            &IoStatusBlock,
            FileBuffer,
            fsi.EndOfFile.LowPart,
            NULL,
            NULL);

        if (Status == STATUS_PENDING)
            Status = NtWaitForSingleObject(hEvent, TRUE, NULL);

        if (NT_SUCCESS(Status)) {

            //
            // Call hashing callback.
            //
            bResult = HashCallback(
                FileBuffer,
                fsi.EndOfFile.LowPart,
                Hash,
                HashLength);

            if (bResult)
                Status = STATUS_SUCCESS;
            else
                Status = STATUS_UNSUCCESSFUL;
        }

    }
    __finally {

        //
        // Cleanup.
        //
        if (hFile) NtClose(hFile);
        if (hEvent) NtClose(hEvent);
        if (FileBuffer) supHeapFree(FileBuffer);
        if (NtFileName.Buffer) RtlFreeUnicodeString(&NtFileName);
    }

    SetLastError(RtlNtStatusToDosError(Status));
    return (NT_SUCCESS(Status));
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

    bResult = FALSE;
    InitializeObjectAttributes(&attr, FileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    Status = NtQueryFullAttributesFile(&attr, &fna);
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
* supJumpToFile
*
* Purpose:
*
* Open explorer window for given path.
*
*/
BOOLEAN supJumpToFile(
    _In_ LPWSTR lpFilePath
)
{
    LPITEMIDLIST IIDL;
    HRESULT hr = E_FAIL;

    if (lpFilePath == NULL)
        return FALSE;

    IIDL = ILCreateFromPath(lpFilePath);
    if (IIDL) {
        hr = SHOpenFolderAndSelectItems(IIDL, 0, NULL, 0);
        ILFree(IIDL);
    }

    return (SUCCEEDED(hr));
}

/*
* supShellExecuteVerb
*
* Purpose:
*
* Shell execute for given verb (explore, properties).
*
*/
VOID supShellExecuteVerb(
    _In_ HWND hwnd,
    _In_ LPWSTR lpFilePath,
    _In_opt_ LPWSTR lpDirectory,
    _In_ LPWSTR lpVerb
)
{
    SHELLEXECUTEINFO ShExec;

    RtlSecureZeroMemory(&ShExec, sizeof(SHELLEXECUTEINFO));
    ShExec.cbSize = sizeof(SHELLEXECUTEINFO);
    ShExec.fMask = SEE_MASK_INVOKEIDLIST | SEE_MASK_FLAG_NO_UI;
    ShExec.hwnd = hwnd;
    ShExec.lpVerb = lpVerb;
    ShExec.lpFile = lpFilePath;
    ShExec.nShow = SW_SHOWNORMAL;
    ShExec.lpDirectory = lpDirectory;
    ShellExecuteEx(&ShExec);
}

/*
* supRunSearchQueryGoogle
*
* Purpose:
*
* Search LookupValue in Google.
*
*/
BOOL supRunSearchQueryGoogle(
    _In_ HWND hwnd,
    _In_reads_bytes_(LookupValueLength) LPWSTR LookupValue,
    _In_ SIZE_T LookupValueLength
)
{
    BOOL bResult;
    SIZE_T Size;
    LPWSTR lpGoogleRequest;
    SHELLEXECUTEINFO ShExec;

    if (LookupValueLength == 0)
        return FALSE;

    Size = DM_GOOGLE_SEARCH_LENGTH + LookupValueLength + sizeof(WCHAR);
    lpGoogleRequest = supHeapAlloc(Size);
    if (lpGoogleRequest == NULL)
        return FALSE;

    _strcpy(lpGoogleRequest, DM_GOOLGE_SEARCH);
    _strcat(lpGoogleRequest, LookupValue);

    RtlSecureZeroMemory(&ShExec, sizeof(SHELLEXECUTEINFO));
    ShExec.cbSize = sizeof(SHELLEXECUTEINFO);
    ShExec.fMask = SEE_MASK_INVOKEIDLIST | SEE_MASK_FLAG_NO_UI;
    ShExec.hwnd = hwnd;
    ShExec.lpVerb = DM_OPEN_VERB;
    ShExec.lpClass = L"https";
    ShExec.lpFile = lpGoogleRequest;
    ShExec.nShow = SW_SHOWNORMAL;
    bResult = ShellExecuteEx(&ShExec);

    supHeapFree(lpGoogleRequest);
    return bResult;
}

/*
* supWhiteListLegacyAddVgaEntry
*
* Purpose:
*
* Always set default whitelist VGA.dll entry for everything below Windows 8.
*
*/
VOID supWhiteListLegacyAddVgaEntry(
    VOID
)
{
    VERIFY_RESULT vr;
    WCHAR szVgaDll[MAX_PATH * 2];

    SIZE_T Length;
    UCHAR Hash[SHA256_DIGEST_LENGTH];

    _strcpy(szVgaDll, USER_SHARED_DATA->NtSystemRoot);
    _strcat(szVgaDll, VGA_DLL);
    Length = _strlen(szVgaDll) * sizeof(WCHAR);
    RtlSecureZeroMemory(&Hash, sizeof(Hash));

    //
    // Calculate sha256 hash for vga.dll
    //
    if (supHashFile(szVgaDll, &Hash, SHA256_DIGEST_LENGTH, supSha256Buffer)) {
        //
        // Verify digital signature of file.
        // If it trusted then add file hash to whitelist.
        //
        vr = DmVerifyFile(szVgaDll);
        if (vr == VrTrusted) {

            //
            // Add to whitelist with silentapprove flag.
            //
            KnownDriversAddEntry(0, ENTRY_FLAGS_SILENTAPPROVE, szVgaDll, Length,
                Hash, SHA256_DIGEST_LENGTH, NULL);

        }
    }
}

/*
* supReadWhiteList
*
* Purpose:
*
* Read whitelist from registry.
* If whitelist registry data not found, create default whitelist.
*
*/
BOOL supReadWhiteList(
    _In_ HKEY RootKey
)
{
    BOOL bCond = FALSE, bResult = FALSE;
    LRESULT lRet;
    DWORD cValues = 0, cbData = 0, dwType = 0;
    HKEY hSubKey = NULL;
    DWORD i;

    SIZE_T Length;

    WCHAR szValue[MAX_PATH];
    KDRVPACKET KdEntryPacket;

    do {

        lRet = RegOpenKeyEx(RootKey, DM_WHITELIST_KEY, 0, KEY_READ, &hSubKey);
        if (lRet != ERROR_SUCCESS)
            break;

        lRet = RegQueryInfoKey(hSubKey, NULL, NULL, NULL, NULL, NULL, NULL,
            &cValues, NULL, NULL, NULL, NULL);
        if (lRet != ERROR_SUCCESS)
            break;

        //
        // Is list empty?
        //
        if (cValues == 0)
            break;

        //
        // Query each value.
        //
        RtlSecureZeroMemory(szValue, sizeof(szValue));
        for (i = 0; i < cValues; i++) {

            _strcpy(szValue, DM_WHITELIST_VALUE);
            ultostr(i, _strend(szValue));
            cbData = sizeof(KDRVPACKET);
            dwType = 0;

            RtlSecureZeroMemory(&KdEntryPacket, sizeof(KdEntryPacket));

            lRet = RegQueryValueEx(
                hSubKey,
                szValue,
                NULL,
                &dwType,
                (LPBYTE)&KdEntryPacket,
                &cbData);

            //
            // Is it in REG_BINARY format?
            //
            if (dwType != REG_BINARY)
                continue;

            //
            // Check if buffer filled.
            //
            if (cbData != sizeof(KDRVPACKET))
                continue;

            Length = _strlen(KdEntryPacket.DriverName) * sizeof(WCHAR);

            bResult = (KnownDriversAddEntry(
                0,
                ENTRY_FLAGS_DEFAULT,
                KdEntryPacket.DriverName,
                Length,
                KdEntryPacket.HashValue,
                SHA256_DIGEST_LENGTH,
                NULL) != NULL);

        }

    } while (bCond);

    if (hSubKey) RegCloseKey(hSubKey);

    return bResult;
}

typedef struct _WL_ENUM {
    HKEY hRootKey;
    DWORD Index;
} WL_ENUM, *PWL_ENUM;

/*
* supListWriteToRegistry
*
* Purpose:
*
* Callback to write whitelist entry to registry.
*
*/
VOID CALLBACK supListWriteToRegistry(
    _In_ PVOID Context,
    _In_ PKDRVENTRY Entry,
    _Inout_ PBOOLEAN StopEnumeration
)
{
    LRESULT lRet;
    PWL_ENUM EnumContext = (PWL_ENUM)Context;
    WCHAR szValue[MAX_PATH];

    RtlSecureZeroMemory(szValue, sizeof(szValue));
    _strcpy(szValue, DM_WHITELIST_VALUE);
    ultostr(EnumContext->Index, _strend(szValue));

    lRet = RegSetValueEx(
        EnumContext->hRootKey,
        szValue,
        0,
        REG_BINARY,
        (BYTE*)&Entry->Packet,
        sizeof(KDRVPACKET));

    EnumContext->Index++;

    if (lRet != ERROR_SUCCESS)
        *StopEnumeration = TRUE;
}

/*
* supWriteWhiteList
*
* Purpose:
*
* Write whitelist to registry.
*
*/
VOID supWriteWhiteList(
    _In_ HKEY RootKey
)
{
    BOOL bCond = FALSE;
    LRESULT lRet;

    HKEY hSubKey = NULL;

    WL_ENUM CallbackContext;

    do {

        RegDeleteKey(RootKey, DM_WHITELIST_KEY);

        lRet = RegCreateKeyEx(
            RootKey,
            DM_WHITELIST_KEY,
            0,
            NULL,
            REG_OPTION_NON_VOLATILE,
            KEY_ALL_ACCESS,
            NULL,
            &hSubKey,
            NULL);

        if (lRet != ERROR_SUCCESS)
            break;

        CallbackContext.hRootKey = hSubKey;
        CallbackContext.Index = 0;

        KnownDriversEnumList(supListWriteToRegistry, &CallbackContext);

    } while (bCond);
    if (hSubKey) RegCloseKey(hSubKey);

}

VOID supxxxTestFileExists(
    VOID
)
{
    BOOLEAN bResult;
    WCHAR szBuffer[MAX_PATH + 1];
    UNICODE_STRING str;

    _strcpy(szBuffer, L"\\??\\C:\\windows");

    str.Buffer = NULL;
    str.Length = 0;
    str.MaximumLength = 0;
    RtlInitUnicodeString(&str, szBuffer);
    bResult = supFileExists(&str);
    if (bResult)
        OutputDebugString(TEXT("File exists"));
    else
        OutputDebugString(TEXT("Not found"));
}

VOID supxxxTestHash(
    VOID
)
{
    BOOLEAN bResult;
    ULONG l;

    UCHAR Sha256[SHA256_DIGEST_LENGTH];
    UCHAR Sha256Str[SHA256_HASH_STRING_LENGTH + 1];

    WCHAR szBuffer[MAX_PATH + 1];


    GetCommandLineParam(GetCommandLine(), 0, szBuffer, MAX_PATH * sizeof(WCHAR), &l);
    if (l == 0)
        return;

    bResult = supHashFile(
        szBuffer,
        &Sha256,
        SHA256_DIGEST_LENGTH,
        supSha256Buffer);

    if (bResult) {
        RtlSecureZeroMemory(&Sha256Str, sizeof(Sha256Str));

        supPrintHash(
            (PUCHAR)&Sha256,
            SHA256_DIGEST_LENGTH,
            (PUCHAR)&Sha256Str,
            SHA256_HASH_STRING_LENGTH,
            FALSE);

        OutputDebugStringA((LPCSTR)Sha256Str);
    }
    else
    {
        OutputDebugString(TEXT("Error calculating self hash"));
    }
}

VOID supxxxTestKD(
    VOID
)
{
    SIZE_T Length;
    ULONG State = 0;
    WCHAR szBuffer[MAX_PATH + 1];

    UCHAR Hash[SHA256_DIGEST_LENGTH];

    //put some random trash
    RtlSecureZeroMemory(&Hash, sizeof(Hash));
    _strcpy(szBuffer, L"c:\\windows\\system32\\drivers\\acpi.sys");
    Length = _strlen(szBuffer) * sizeof(WCHAR);
    supHashFile(szBuffer, &Hash, SHA256_DIGEST_LENGTH, supSha256Buffer);
    KnownDriversAddEntry(0, ENTRY_FLAGS_DEFAULT, szBuffer, Length, Hash, sizeof(Hash), NULL);

    RtlSecureZeroMemory(&Hash, sizeof(Hash));
    _strcpy(szBuffer, L"c:\\windows\\system32\\drivers\\fltmgr.sys");
    Length = _strlen(szBuffer) * sizeof(WCHAR);
    supHashFile(szBuffer, &Hash, SHA256_DIGEST_LENGTH, supSha256Buffer);
    KnownDriversAddEntry(0, ENTRY_FLAGS_DEFAULT, szBuffer, Length, Hash, sizeof(Hash), NULL);

    RtlSecureZeroMemory(&Hash, sizeof(Hash));
    _strcpy(szBuffer, L"c:\\windows\\system32\\drivers\\ntfs.sys");
    Length = _strlen(szBuffer) * sizeof(WCHAR);
    supHashFile(szBuffer, &Hash, SHA256_DIGEST_LENGTH, supSha256Buffer);
    KnownDriversAddEntry(0, ENTRY_FLAGS_DEFAULT, szBuffer, Length, Hash, sizeof(Hash), NULL);

    //duplicate test
    RtlSecureZeroMemory(&Hash, sizeof(Hash));
    _strcpy(szBuffer, L"c:\\windows\\system32\\drivers\\acpi.sys");
    Length = _strlen(szBuffer) * sizeof(WCHAR);
    supHashFile(szBuffer, &Hash, SHA256_DIGEST_LENGTH, supSha256Buffer);
    KnownDriversAddEntry(0, ENTRY_FLAGS_DEFAULT, szBuffer, Length, Hash, sizeof(Hash), &State);
}
