/*******************************************************************************
*
*  (C) COPYRIGHT Fyyre & EP_X0FF, 2010 - 2017
*
*  TITLE:       CONFIGDLG.C
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

BOOL g_bOutputDirectoryChange = FALSE;

/*
* ConfigChangeOutputDirectory
*
* Purpose:
*
* Change Output Directory button handler.
*
*/
VOID ConfigChangeOutputDirectory(
    _In_ HWND hDlg
)
{
    SIZE_T Length;
    WCHAR szNewDirectory[MAX_PATH * 2];

    RtlSecureZeroMemory(szNewDirectory, sizeof(szNewDirectory));

    if (supSelectDirectory(hDlg, 
        DM_EVENT_SELECT_OUTDIR, 
        szNewDirectory, 
        MAX_PATH))
    {
        //
        // Concat delimiter if not exist.
        //
        Length = _strlen(szNewDirectory);
        if (szNewDirectory[Length - 1] != L'\\') {
            szNewDirectory[Length] = L'\\';
            szNewDirectory[Length + 1] = 0;
        }
        SetDlgItemText(hDlg, ID_OUTPUTDIRECTORY, szNewDirectory);
        g_bOutputDirectoryChange = TRUE;
    }
}

/*
* ConfigDialogInit
*
* Purpose:
*
* Displays program settings.
*
*/
VOID ConfigDialogInit(
    _In_ HWND hDlg
)
{
    g_bOutputDirectoryChange = FALSE;

    SetDlgItemText(hDlg, ID_OUTPUTDIRECTORY, g_OutputDirectory.Buffer);

    CheckDlgButton(hDlg, ID_CB_DISPGRIDLINES,
        (g_ctx.Settings.ShowGridLines != FALSE) ? BST_CHECKED : BST_UNCHECKED);

    CheckDlgButton(hDlg, ID_CB_MANUALCONFIRM,
        (g_ctx.Settings.ManualConfirmDriverLoading != FALSE) ? BST_CHECKED : BST_UNCHECKED);

    SetFocus(GetDlgItem(hDlg, IDOK));
}

/*
* ConfigDialogApplySettings
*
* Purpose:
*
* Change program settings depending on what user selected.
*
*/
VOID ConfigDialogApplySettings(
    _In_ HWND hDlg
)
{
    DWORD dwStyle;
    WCHAR szBuffer[MAX_PATH + 1];
    DRVMON_EVENT AppEvent;

    //
    // Show Grid Lines setting.
    //
    g_ctx.Settings.ShowGridLines = (BOOLEAN)
        (IsDlgButtonChecked(hDlg, ID_CB_DISPGRIDLINES) == BST_CHECKED);

    dwStyle = ListView_GetExtendedListViewStyle(g_ctx.EventList);

    if (g_ctx.Settings.ShowGridLines)
        dwStyle |= LVS_EX_GRIDLINES;
    else
        dwStyle &= ~LVS_EX_GRIDLINES;

    ListView_SetExtendedListViewStyle(g_ctx.EventList,
        (WPARAM)dwStyle);

    //
    // Manual Confirm Driver Loading setting.
    //
    g_ctx.Settings.ManualConfirmDriverLoading = (BOOLEAN)
        (IsDlgButtonChecked(hDlg, ID_CB_MANUALCONFIRM) == BST_CHECKED);

    if (g_ctx.Settings.ManualConfirmDriverLoading) {
        
        g_ctx.DrvMonFlags |= DRVMON_FILTER_ENABLED;

        //
        // Block Drivers Loading setting is incompatible with Manual Confirm.
        // Turn off Block driver loading setting.
        //
        if (g_ctx.Settings.BlockDrivers) {
            g_ctx.Settings.BlockDrivers = FALSE;
            g_ctx.DrvMonFlags &= ~DRVMON_BLOCK_DRIVERS_LOADING;

            CheckMenuItem(GetMenu(g_ctx.MainWindow), ID_MONITOR_BLOCKDRIVERLOADING, MF_UNCHECKED);
            DmUIChangeImageForButton(g_ctx.ToolBar, ID_MONITOR_BLOCKDRIVERLOADING, IDX_BLOCKBUTTON_DISABLE);

            RtlSecureZeroMemory(&AppEvent, sizeof(AppEvent));
            GetSystemTimeAsFileTime((LPFILETIME)&AppEvent.LogTime);
            AppEvent.EventType = EVENT_TYPE_INFORMATION;
            _strcpy(AppEvent.wEvent, DM_EVENT_BLOCK_OFF);
            DmUIAddEvent(&AppEvent);
        }
    }
    else {
        g_ctx.DrvMonFlags &= ~DRVMON_FILTER_ENABLED;
    }

    DmSetInternalFlags(g_ctx.DrvMonFlags);

    //
    // Set output directory but only if there is any change made.
    //
    if (g_bOutputDirectoryChange != FALSE) {
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        if (GetDlgItemText(hDlg, ID_OUTPUTDIRECTORY, szBuffer, MAX_PATH)) {
            _strcpy(g_szOutputDirectory, szBuffer);
            RtlInitUnicodeString(&g_OutputDirectory, g_szOutputDirectory);
            //
            // Call driver to change output directory and output change as event.
            //
            if (DmSetOutputDirectory(&g_OutputDirectory))
                DmUIAddChangeOutputDirectoryEvent(szBuffer, MAX_PATH);

            g_bOutputDirectoryChange = FALSE;
        }
    }
}

/*
* ConfigDialogProc
*
* Purpose:
*
* Config Dialog Window Dialog Procedure
*
* During WM_INITDIALOG centers window and initializes system info
*
*/
INT_PTR CALLBACK ConfigDialogProc(
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
        ConfigDialogInit(hwndDlg);
        break;

    case WM_COMMAND:

        switch (LOWORD(wParam)) {

        case ID_BUTTONBROWSE:
            ConfigChangeOutputDirectory(hwndDlg);
            break;
        case IDOK:
            ConfigDialogApplySettings(hwndDlg);
            EndDialog(hwndDlg, S_OK);
            break;
        case IDCANCEL:
            EndDialog(hwndDlg, S_OK);
            break;
        default:
            break;
        }
        break;

    default:
        break;
    }
    return 0;
}
