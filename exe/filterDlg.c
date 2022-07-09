/*******************************************************************************
*
*  (C) COPYRIGHT Fyyre & EP_X0FF, 2010 - 2017
*
*  TITLE:       FILTERDLG.C
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

#define FilterDlgMenuProp L"FltDlgMenu"

/*
* FilterDialogChangeSettings
*
* Purpose:
*
* Checkbox "Confirm Driver Loading Manually" handler.
*
*/
VOID FilterDialogChangeSettings(
    _In_ HWND hDlg
)
{
    UINT uResult;

    uResult = IsDlgButtonChecked(hDlg, ID_CB_MANUALCONFIRM);

    g_ctx.Settings.ManualConfirmDriverLoading = (uResult == BST_CHECKED);

    if (g_ctx.Settings.ManualConfirmDriverLoading == FALSE) {
        g_ctx.DrvMonFlags &= ~DRVMON_FILTER_ENABLED;
    }
    else {
        g_ctx.DrvMonFlags |= DRVMON_FILTER_ENABLED;
    }

    DmSetInternalFlags(g_ctx.DrvMonFlags);
}

/*
* FilterDialogInit
*
* Purpose:
*
* Displays filter packet data and settings.
*
*/
VOID FilterDialogInit(
    _In_ HWND hDlg,
    _In_ PDRVMON_PACKET Packet
)
{
    LPWSTR lpText;
    HMENU hMenu;

    __try {

        SetDlgItemText(hDlg, ID_DRVNAME, Packet->DriverName);

        if ((Packet->Flags & PACKET_FLAGS_DRIVER_WHITELISTED) > 0) {
            lpText = TEXT("Yes");
        }
        else {
            lpText = TEXT("No");
        }

        SetDlgItemText(hDlg, ID_DRVSTATUS, lpText);

        CheckDlgButton(hDlg, ID_CB_MANUALCONFIRM,
            (g_ctx.Settings.ManualConfirmDriverLoading != FALSE) ? BST_CHECKED : BST_UNCHECKED);

        hMenu = LoadMenu(g_ctx.hInstance, MAKEINTRESOURCE(IDR_MENU3));
        if (hMenu) {
            SetMenu(GetDlgItem(hDlg, ID_BUTTON_LOOKUP), GetSubMenu(hMenu, 0));
            SetProp(hDlg, FilterDlgMenuProp, hMenu);
        }

        SetFocus(GetDlgItem(hDlg, ID_BUTTON_ALLOW));
    }
    __except (exceptFilter(GetExceptionCode(), GetExceptionInformation())) {
        return;
    }
}

/*
* FilterDialogHandleWMCommand
*
* Purpose:
*
* WM_COMMAND handler.
*
*/
VOID FilterDialogHandleWMCommand(
    _In_ HWND   hwndDlg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
)
{
    HANDLE hMenu;
    POINT pt1;

    UINT NtPrefix = 0;
    SIZE_T Length = 0;

    LPWSTR lpFileName;

    UCHAR Hash[SHA256_DIGEST_LENGTH];
    CHAR szHash[SHA256_HASH_STRING_LENGTH + 1];
    WCHAR wszHash[SHA256_HASH_STRING_LENGTH + 1];

    UNREFERENCED_PARAMETER(lParam);

    switch (LOWORD(wParam)) {

    case ID_JUMPTO:
    case ID_PROPERTIES:
    case ID_SEARCHONLINE_BYHASH:
    case ID_SEARCHONLINE_BYNAME:

        Length = _strlen(g_FltPacket.DriverName);
        if (Length == 0)
            return;

        NtPrefix = supIsNtNamePrefix(g_FltPacket.DriverName, Length * sizeof(WCHAR));
        break;
    }

    switch (LOWORD(wParam)) {

    case ID_JUMPTO:
        RtlSecureZeroMemory(g_szTempDrvName, sizeof(g_szTempDrvName));
        if (_filepath(&g_FltPacket.DriverName[NtPrefix], g_szTempDrvName))
            supJumpToFile(g_szTempDrvName);
        break;

    case ID_PROPERTIES:
        supShellExecuteVerb(hwndDlg, &g_FltPacket.DriverName[NtPrefix], NULL, DM_PROPERTIES_VERB);
        break;

    case ID_SEARCHONLINE_BYHASH:

        RtlSecureZeroMemory(Hash, sizeof(Hash));
        if (supHashFile(&g_FltPacket.DriverName[NtPrefix], Hash, SHA256_DIGEST_LENGTH, supSha256Buffer)) {
            RtlSecureZeroMemory(szHash, sizeof(szHash));
            if (supPrintHash(
                (PUCHAR)&Hash,
                SHA256_DIGEST_LENGTH,
                (PUCHAR)&szHash,
                SHA256_HASH_STRING_LENGTH,
                FALSE))
            {
                RtlSecureZeroMemory(wszHash, sizeof(wszHash));

                MultiByteToWideChar(
                    CP_ACP,
                    0,
                    szHash,
                    (INT)_strlen_a(szHash),
                    wszHash,
                    SHA256_HASH_STRING_LENGTH);

                supRunSearchQueryGoogle(hwndDlg, wszHash, sizeof(wszHash));
            }
        }
        break;

    case ID_SEARCHONLINE_BYNAME:

        lpFileName = _filename(&g_FltPacket.DriverName[NtPrefix]);
        if (lpFileName) {
            Length = _strlen(lpFileName);
            supRunSearchQueryGoogle(hwndDlg, lpFileName, Length * sizeof(WCHAR));
        }

        break;


    case ID_BUTTON_LOOKUP:
        hMenu = GetProp(hwndDlg, FilterDlgMenuProp);
        if (GetCursorPos(&pt1)) {
            TrackPopupMenu(GetSubMenu(hMenu, 0),
                TPM_RIGHTBUTTON | TPM_LEFTALIGN,
                pt1.x, pt1.y,
                0, hwndDlg,
                NULL);
        }
        break;

    case ID_BUTTON_BLOCK:
        g_FltPacket.UserAnswer = IDNO;
        EndDialog(hwndDlg, S_OK);
        break;

    case ID_BUTTON_ALLOW:
        g_FltPacket.UserAnswer = IDYES;
        EndDialog(hwndDlg, S_OK);
        break;

    case ID_CB_MANUALCONFIRM:
        FilterDialogChangeSettings(hwndDlg);
        break;

    case IDCANCEL:
        EndDialog(hwndDlg, S_OK);
        break;
    default:
        break;

    }
}

/*
* FilterDialogProc
*
* Purpose:
*
* Filter Dialog Window Dialog Procedure
*
* During WM_INITDIALOG centers window and initializes dialog controls.
* lParam is a pointer to DRVMON_PACKET.
*
*/
INT_PTR CALLBACK FilterDialogProc(
    _In_ HWND   hwndDlg,
    _In_ UINT   uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
)
{
    HMENU hMenu;

    switch (uMsg) {

    case WM_INITDIALOG:
        supCenterWindow(hwndDlg);
        InterlockedExchange((LONG*)&g_DrvFltInProgress, TRUE);
        FilterDialogInit(hwndDlg, (PDRVMON_PACKET)lParam);
        break;

    case WM_COMMAND:
        FilterDialogHandleWMCommand(hwndDlg, wParam, lParam);
        break;

    case WM_DESTROY:
        hMenu = GetProp(hwndDlg, FilterDlgMenuProp);
        if (hMenu) DestroyMenu(hMenu);
        RemoveProp(hwndDlg, FilterDlgMenuProp);

        InterlockedExchange((LONG*)&g_DrvFltInProgress, FALSE);
        break;

    default:
        break;
    }
    return 0;
}
