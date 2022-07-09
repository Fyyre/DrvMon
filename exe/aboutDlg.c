/*******************************************************************************
*
*  (C) COPYRIGHT Fyyre & EP_X0FF, 2010 - 2017
*
*  TITLE:       ABOUTDLG.C
*
*  VERSION:     3.00
*
*  DATE:        01 Apr 2017
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

/*
* AboutDialogInit
*
* Purpose:
*
* Displays program version and build information
*
*/
VOID AboutDialogInit(
    HWND hwndDlg
)
{
    WCHAR szBuffer[200];

    RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
    SetDlgItemText(hwndDlg, ID_ABOUT_COPYRIGHT, DM_COPYRIGHT);

    _strcpy(szBuffer, DM_BUILD_STRING);
    MultiByteToWideChar(CP_ACP, 0, __DATE__, (INT)_strlen_a(__DATE__), _strend(szBuffer), 40);
    _strcat(szBuffer, L" ");
    MultiByteToWideChar(CP_ACP, 0, __TIME__, (INT)_strlen_a(__TIME__), _strend(szBuffer), 40);
#if defined _WIN64
    _strcat(szBuffer, L", x64");
#else
    _strcat(szBuffer, L", x86");
#endif
    SetDlgItemText(hwndDlg, ID_ABOUT_BUILDINFO, szBuffer);
    SetDlgItemText(hwndDlg, ID_ABOUT_VERSION, DM_VERSION);

    SetFocus(GetDlgItem(hwndDlg, IDOK));
}

/*
* AboutDialogProc
*
* Purpose:
*
* About Dialog Window Dialog Procedure
*
* During WM_INITDIALOG centers window and initializes system info
*
*/
INT_PTR CALLBACK AboutDialogProc(
    _In_ HWND   hwndDlg,
    _In_ UINT   uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
)
{
    UNREFERENCED_PARAMETER(lParam);

    switch (uMsg) {

    case WM_INITDIALOG:
        supCenterWindow(hwndDlg);
        AboutDialogInit(hwndDlg);
        break;

    case WM_COMMAND:
        if ((LOWORD(wParam) == IDOK) || (LOWORD(wParam) == IDCANCEL))
            EndDialog(hwndDlg, S_OK);
        break;

    default:
        break;
    }
    return 0;
}