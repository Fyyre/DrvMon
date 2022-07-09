/*******************************************************************************
*
*  (C) COPYRIGHT Fyyre & EP_X0FF, 2010 - 2017
*
*  TITLE:       WHITELISTDLG.C
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

HWND g_wlListView;

/*
* WhiteListListViewAdd
*
* Purpose:
*
* Add entry to to listview.
*
*/
VOID WhiteListListViewAdd(
    _In_ HWND ListView,
    _In_ PKDRVENTRY Entry
)
{
    BOOL bConverted;
    INT index;
    LVITEM lvitem;

    CHAR szHash[SHA256_HASH_STRING_LENGTH + 1];
    WCHAR wszHash[SHA256_HASH_STRING_LENGTH + 1];

    if (ListView == 0)
        return;

    RtlSecureZeroMemory(&lvitem, sizeof(lvitem));
    lvitem.mask = LVIF_TEXT | LVIF_PARAM;
    lvitem.iSubItem = 0;
    lvitem.pszText = Entry->Packet.DriverName;
    lvitem.lParam = (LPARAM)Entry;
    index = ListView_InsertItem(ListView, &lvitem);

    RtlSecureZeroMemory(szHash, sizeof(szHash));
    RtlSecureZeroMemory(wszHash, sizeof(wszHash));

    bConverted = supPrintHash(
        (PUCHAR)&Entry->Packet.HashValue,
        SHA256_DIGEST_LENGTH,
        (PUCHAR)&szHash,
        SHA256_HASH_STRING_LENGTH,
        TRUE);

    if (bConverted) {
        MultiByteToWideChar(
            CP_ACP,
            0,
            szHash,
            (INT)_strlen_a(szHash),
            wszHash,
            SHA256_HASH_STRING_LENGTH);
    }

    lvitem.mask = LVIF_TEXT;
    lvitem.iSubItem = 1;
    lvitem.pszText = wszHash;
    lvitem.iItem = index;
    ListView_SetItem(ListView, &lvitem);
}

/*
* WhiteListEnum
*
* Purpose:
*
* Enum entries in whitelist and output them to listview.
*
*/
VOID CALLBACK WhiteListEnum(
    _In_opt_ PVOID Context,
    _In_ PKDRVENTRY Entry,
    _Inout_ PBOOLEAN StopEnumeration
)
{
    HWND ListView = (HWND)Context;

    if (ListView) {

        WhiteListListViewAdd(ListView, Entry);
    }
    *StopEnumeration = FALSE;
}

/*
* WhiteListDisplayEntryHash
*
* Purpose:
*
* Query and display entry hash.
*
*/
VOID WhiteListDisplayEntryHash(
    _In_ HWND hDlg,
    _In_ HWND ListView,
    _In_ INT nSelected
)
{
    BOOLEAN bConverted = FALSE;
    KDRVENTRY Entry;
    LVITEM lvitem;

    CHAR szHash[SHA256_HASH_STRING_LENGTH + 1];
    WCHAR wszHash[SHA256_HASH_STRING_LENGTH + 1];

    //
    // Query associated event info.
    //
    RtlSecureZeroMemory(&lvitem, sizeof(lvitem));

    lvitem.mask = LVIF_PARAM;
    lvitem.iItem = nSelected;
    if (!ListView_GetItem(ListView, &lvitem))
        return;

    if (lvitem.lParam == 0)
        return;

    __try {
        RtlCopyMemory(&Entry, (PVOID)lvitem.lParam, sizeof(KDRVENTRY));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return;
    }

    RtlSecureZeroMemory(szHash, sizeof(szHash));
    RtlSecureZeroMemory(wszHash, sizeof(wszHash));

    bConverted = supPrintHash(
        (PUCHAR)&Entry.Packet.HashValue,
        SHA256_DIGEST_LENGTH,
        (PUCHAR)&szHash,
        SHA256_HASH_STRING_LENGTH,
        TRUE);

    if (bConverted) {
        MultiByteToWideChar(
            CP_ACP,
            0,
            szHash,
            (INT)_strlen_a(szHash),
            wszHash,
            SHA256_HASH_STRING_LENGTH);

        SetDlgItemText(hDlg, ID_ENTRY_HASH, wszHash);
    }
}

/*
* WhiteListAddEntry
*
* Purpose:
*
* Browse for file and add it to whitelist and inform driver.
*
*/
VOID WhiteListAddEntry(
    _In_ HWND hDlg,
    _In_ HWND ListView
)
{
    BOOL bAdded;
    ULONG State = 0;
    SIZE_T Length;

    LPWSTR lpEvent;

    PKDRVENTRY Entry = NULL;

    WCHAR szFileName[MAX_PATH + 1];

    UCHAR Hash[SHA256_DIGEST_LENGTH];

    //
    // Launch open dialog to select file.
    //
    RtlSecureZeroMemory(szFileName, sizeof(szFileName));
    if (!supOpenDialogExecute(
        hDlg,
        (LPWSTR)&szFileName,
        DM_OPENDLG_ALL_FILTER)) return;

    //
    // Create hash for selected file.
    //
    RtlSecureZeroMemory(Hash, sizeof(Hash));
    if (!supHashFile(
        szFileName,
        &Hash,
        SHA256_DIGEST_LENGTH,
        supSha256Buffer))
    {
        MessageBox(hDlg, DM_ERROR_CALC_HASH, PROGRAMNAME, MB_ICONERROR);
        return;
    }

    //
    // Add entry to program whitelist.
    //
    Length = _strlen(szFileName) * sizeof(WCHAR);

    Entry = KnownDriversAddEntry(
        0,
        ENTRY_FLAGS_DEFAULT,
        szFileName,
        Length,
        Hash,
        SHA256_DIGEST_LENGTH,
        &State);

    //
    // Handle error.
    //
    bAdded = (Entry != NULL);
    if (bAdded == FALSE) {

        if (State == ERROR_ALREADY_EXISTS)
            lpEvent = DM_WHITELIST_DUPLICATE;
        else
            lpEvent = DM_WHITELIST_ADD_ERROR;

        MessageBox(hDlg, lpEvent, PROGRAMNAME, MB_ICONERROR);
        return;
    }

    //
    // No error, send driver request.
    //
    bAdded = DmManageWhiteList(TRUE, 0, ENTRY_FLAGS_DEFAULT, szFileName, Length, Hash, sizeof(Hash));
    if (bAdded == FALSE) {

        //
        // Driver request error, remove entry as we cannot send it to driver.
        //
        lpEvent = DM_ERROR_SEND_REQUEST;
        MessageBox(hDlg, lpEvent, PROGRAMNAME, MB_ICONERROR);

        KnownDriversRemoveEntry(DELETE_BY_HASH, &Entry->Packet);
    }
    else {
        //
        // Everything OK, display new item in listview.
        //
        WhiteListListViewAdd(ListView, Entry);
    }
}

/*
* WhiteListRemoveEntry
*
* Purpose:
*
* Remove selected entry from whitelist and inform driver.
*
*/
VOID WhiteListRemoveEntry(
    _In_ HWND hDlg,
    _In_ HWND ListView
)
{
    INT nSelected;
    SIZE_T Length;
    LVITEM lvitem;

    KDRVENTRY Entry;

    if (ListView_GetSelectedCount(ListView) == 0)
        return;

    nSelected = ListView_GetSelectionMark(ListView);
    if (nSelected < 0)
        return;

    //
    // Query associated event info.
    //
    RtlSecureZeroMemory(&lvitem, sizeof(lvitem));

    lvitem.mask = LVIF_PARAM;
    lvitem.iItem = nSelected;
    if (!ListView_GetItem(ListView, &lvitem))
        return;

    if (lvitem.lParam == 0)
        return;

    RtlSecureZeroMemory(&Entry, sizeof(Entry));

    __try {
        RtlCopyMemory(&Entry, (PVOID)lvitem.lParam, sizeof(KDRVENTRY));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return;
    }

    if (MessageBox(hDlg,
        DM_CONFIRM_DELETE,
        PROGRAMNAME,
        MB_ICONQUESTION | MB_YESNO) == IDNO) return;

    Length = _strlen(Entry.Packet.DriverName) * sizeof(WCHAR);
    if (Length) {

        if (KnownDriversRemoveEntry(DELETE_BY_HASH, &Entry.Packet)) {

            DmManageWhiteList(FALSE,
                Entry.Tag,
                Entry.Flags,
                Entry.Packet.DriverName,
                Length,
                Entry.Packet.HashValue,
                sizeof(Entry.Packet.HashValue));

            ListView_DeleteItem(ListView, lvitem.iItem);

            SetDlgItemText(hDlg, ID_ENTRY_HASH, TEXT(""));
        }
    }
}

/*
* WhiteListDialogInit
*
* Purpose:
*
* Displays program settings.
*
*/
VOID WhiteListDialogInit(
    _In_ HWND hDlg
)
{
    LVCOLUMN col;
    DWORD dwStyle;

    g_wlListView = GetDlgItem(hDlg, ID_WHITELIST);

    if (g_wlListView) {

        dwStyle = LVS_EX_FULLROWSELECT | LVS_EX_LABELTIP | LVS_EX_DOUBLEBUFFER;
        if (g_ctx.Settings.ShowGridLines)
            dwStyle |= LVS_EX_GRIDLINES;

        ListView_SetExtendedListViewStyle(g_wlListView, dwStyle);

        RtlSecureZeroMemory(&col, sizeof(col));
        col.mask = LVCF_TEXT | LVCF_SUBITEM | LVCF_FMT | LVCF_WIDTH | LVCF_ORDER;
        col.iSubItem = 1;
        col.pszText = LV_FILENAME;
        col.fmt = LVCFMT_LEFT;
        col.iOrder = 0;
        col.iImage = -1;
        col.cx = 220;
        ListView_InsertColumn(g_wlListView, 1, &col);

        col.iSubItem = 2;
        col.pszText = LV_HASH;
        col.iOrder = 1;
        col.iImage = -1;
        col.cx = 400;
        ListView_InsertColumn(g_wlListView, 2, &col);
        KnownDriversEnumList(WhiteListEnum, (PVOID)g_wlListView);
    }

    SetDlgItemText(hDlg, ID_ENTRY_HASH, TEXT(""));

    SetFocus(GetDlgItem(hDlg, IDCANCEL));
}

/*
* WhiteListDialogProc
*
* Purpose:
*
* Whitelist Dialog Window Dialog Procedure
*
* During WM_INITDIALOG centers window and initializes whitelist.
*
*/
INT_PTR CALLBACK WhiteListDialogProc(
    _In_ HWND   hwndDlg,
    _In_ UINT   uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
)
{
    LPNMHDR hdr = (LPNMHDR)lParam;
    NMLISTVIEW *plv = NULL;

    switch (uMsg) {

    case WM_INITDIALOG:
        supCenterWindow(hwndDlg);
        WhiteListDialogInit(hwndDlg);
        break;

    case WM_NOTIFY:
        if (hdr) {
            if (hdr->hwndFrom == g_wlListView) {
                switch (hdr->code) {
                case LVN_ITEMCHANGED:
                case LVN_ITEMCHANGING:
                case NM_CLICK:
                    plv = (NMLISTVIEW *)lParam;
                    if (plv) {
                        WhiteListDisplayEntryHash(hwndDlg, g_wlListView, plv->iItem);
                    }
                    break;
                }
            }
        }
        break;

    case WM_COMMAND:

        switch (LOWORD(wParam)) {

        case ID_BUTTON_ADDWL:
            WhiteListAddEntry(hwndDlg, GetDlgItem(hwndDlg, ID_WHITELIST));
            break;

        case ID_BUTTON_REMOVEWL:
            WhiteListRemoveEntry(hwndDlg, GetDlgItem(hwndDlg, ID_WHITELIST));
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
