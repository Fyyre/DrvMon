/*******************************************************************************
*
*  (C) COPYRIGHT Fyyre & EP_X0FF, 2010 - 2017
*
*  TITLE:       GUI.C
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

fnptr_snwprintf_s _snwprintf_s;

PVOID   EventListHeap = NULL;
ULONG   g_uTotalEvents = 0;
BOOL    g_DrvFltInProgress = FALSE;

DRVMON_PACKET g_FltPacket;

/*
* DmpUIChangeAutoScroll
*
* Purpose:
*
* AutoScrool menu handler.
*
*/
VOID DmpUIChangeAutoScroll(
    _In_ HWND hDlg
)
{
    LPWSTR lpEvent;
    DRVMON_EVENT AppEvent;

    g_ctx.Settings.AutoScroll = !g_ctx.Settings.AutoScroll;

    CheckMenuItem(GetMenu(hDlg), ID_MONITOR_AUTOSCROLL,
        (g_ctx.Settings.AutoScroll != FALSE) ?
        MF_BYCOMMAND | MF_CHECKED : MF_BYCOMMAND | MF_UNCHECKED);

    DmUIChangeImageForButton(g_ctx.ToolBar,
        ID_MONITOR_AUTOSCROLL,
        (g_ctx.Settings.AutoScroll != FALSE) ?
        IDX_AUTOSCROLLBUTTON_ENABLE : IDX_AUTOSCROLLBUTTON_DISABLE);

    RtlSecureZeroMemory(&AppEvent, sizeof(AppEvent));
    GetSystemTimeAsFileTime((LPFILETIME)&AppEvent.LogTime);
    AppEvent.EventType = EVENT_TYPE_INFORMATION;

    if (g_ctx.Settings.AutoScroll != FALSE)
        lpEvent = DM_EVENT_AUTOSCROLL_ON;
    else
        lpEvent = DM_EVENT_AUTOSCROLL_OFF;

    _strcpy(AppEvent.wEvent, lpEvent);
    DmUIAddEvent(&AppEvent);
}

/*
* DmpUIChangeCaptureDrivers
*
* Purpose:
*
* Capture Drivers menu handler.
*
*/
VOID DmpUIChangeCaptureDrivers(
    _In_ HWND hDlg
)
{
    LPWSTR lpEvent;
    DRVMON_EVENT AppEvent;

    g_ctx.Settings.CaptureDrivers = !g_ctx.Settings.CaptureDrivers;

    CheckMenuItem(GetMenu(hDlg), ID_MONITOR_CAPTUREDRIVERS,
        (g_ctx.Settings.CaptureDrivers != FALSE) ?
        MF_BYCOMMAND | MF_CHECKED : MF_BYCOMMAND | MF_UNCHECKED);

    DmUIChangeImageForButton(g_ctx.ToolBar,
        ID_MONITOR_CAPTUREDRIVERS,
        (g_ctx.Settings.CaptureDrivers != FALSE) ?
        IDX_CAPTUREBUTTON_ENABLE : IDX_CAPTUREBUTTON_DISABLE);

    RtlSecureZeroMemory(&AppEvent, sizeof(AppEvent));
    GetSystemTimeAsFileTime((LPFILETIME)&AppEvent.LogTime);
    AppEvent.EventType = EVENT_TYPE_INFORMATION;

    if (g_ctx.Settings.CaptureDrivers != FALSE) {
        lpEvent = DM_EVENT_CAPTURE_ON;
        g_ctx.DrvMonFlags |= DRVMON_CAPTURE_DRIVERS;
    }
    else {
        lpEvent = DM_EVENT_CAPTURE_OFF;
        g_ctx.DrvMonFlags &= ~DRVMON_CAPTURE_DRIVERS;
    }

    DmSetInternalFlags(g_ctx.DrvMonFlags);

    _strcpy(AppEvent.wEvent, lpEvent);
    DmUIAddEvent(&AppEvent);
}

/*
* DmpUIChangeBlockDrivers
*
* Purpose:
*
* Block(Deny) Drivers Loading menu handler.
*
*/
VOID DmpUIChangeBlockDrivers(
    _In_ HWND hDlg
)
{
    LPWSTR lpEvent;
    DRVMON_EVENT AppEvent;

    //
    // User to enable Block Drivers Loading feature.
    // Throw warning.
    //
    if (g_ctx.Settings.BlockDrivers == FALSE) {

        if (g_ctx.Settings.ManualConfirmDriverLoading)
            lpEvent = DM_BLOCK_DRIVERS_WARNING_TYPE_2;
        else
            lpEvent = DM_BLOCK_DRIVERS_WARNING_TYPE_1;

        if (MessageBox(hDlg, lpEvent, PROGRAMNAME, MB_ICONQUESTION | MB_YESNO) == IDNO)
            return;
    }

    g_ctx.Settings.BlockDrivers = !g_ctx.Settings.BlockDrivers;

    CheckMenuItem(GetMenu(hDlg), ID_MONITOR_BLOCKDRIVERLOADING,
        (g_ctx.Settings.BlockDrivers != FALSE) ?
        MF_BYCOMMAND | MF_CHECKED : MF_BYCOMMAND | MF_UNCHECKED);

    DmUIChangeImageForButton(g_ctx.ToolBar,
        ID_MONITOR_BLOCKDRIVERLOADING,
        (g_ctx.Settings.BlockDrivers != FALSE) ?
        IDX_BLOCKBUTTON_ENABLE : IDX_BLOCKBUTTON_DISABLE);


    RtlSecureZeroMemory(&AppEvent, sizeof(AppEvent));
    GetSystemTimeAsFileTime((LPFILETIME)&AppEvent.LogTime);
    AppEvent.EventType = EVENT_TYPE_INFORMATION;

    if (g_ctx.Settings.BlockDrivers != FALSE) {
        lpEvent = DM_EVENT_BLOCK_ON;
        g_ctx.DrvMonFlags |= DRVMON_BLOCK_DRIVERS_LOADING;

        //
        // We are in auto block mode. If manual confirmation enabled disable it.
        //
        if (g_ctx.Settings.ManualConfirmDriverLoading) {
            g_ctx.Settings.ManualConfirmDriverLoading = FALSE;
            g_ctx.DrvMonFlags &= ~DRVMON_FILTER_ENABLED;
        }
    }
    else {
        lpEvent = DM_EVENT_BLOCK_OFF;
        g_ctx.DrvMonFlags &= ~DRVMON_BLOCK_DRIVERS_LOADING;
    }
    DmSetInternalFlags(g_ctx.DrvMonFlags);

    //
    // Output new state event.
    //
    _strcpy(AppEvent.wEvent, lpEvent);
    DmUIAddEvent(&AppEvent);
}

/*
* DmpUIChangeOutputDirectory
*
* Purpose:
*
* Change Output Directory menu handler.
*
*/
VOID DmpUIChangeOutputDirectory(
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

        _strcpy(g_szOutputDirectory, szNewDirectory);
        RtlInitUnicodeString(&g_OutputDirectory, g_szOutputDirectory);

        if (DmSetOutputDirectory(&g_OutputDirectory))
            DmUIAddChangeOutputDirectoryEvent(szNewDirectory, g_OutputDirectory.Length / sizeof(WCHAR));
    }
}

/*
* DmpSaveLog
*
* Purpose:
*
* Save log to file.
*
*/
VOID DmpSaveLog(
    _In_ HWND hWnd
)
{
    HANDLE hFile;
    DWORD bytesIO;

    WCHAR ch = 0xFEFF;
    WCHAR szFileSave[MAX_PATH * 2];
    WCHAR szFieldText[MAXITEMLENGTH];
    WCHAR *lpszOutput = NULL;

    INT cItems, row, subitem;

    RtlSecureZeroMemory(&szFileSave, sizeof(szFileSave));

    _strcpy(szFileSave, DM_DEFAULT_LOG_FILE);
    if (!supSaveDialogExecute(hWnd, szFileSave, DM_SAVEDLG_TXT_FILTER, DM_LOG_EXT))
        return;

    hFile = CreateFile(szFileSave,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        DmShowError(hWnd, TEXT("Error creating log file"));
        return;
    }

    WriteFile(hFile, (LPCVOID)&ch, sizeof(ch), &bytesIO, NULL);

    SetCapture(g_ctx.MainWindow);
    supSetWaitCursor(TRUE);

    __try {
        cItems = ListView_GetItemCount(g_ctx.EventList);

        lpszOutput = supHeapAlloc(MAXITEMLENGTH * NUMCOLUMNS);
        if (lpszOutput) {
            for (row = 0; row < cItems; row++) {
                lpszOutput[0] = 0;
                for (subitem = 0; subitem < NUMCOLUMNS; subitem++) {
                    szFieldText[0] = 0;
                    ListView_GetItemText(g_ctx.EventList, row, subitem, szFieldText, 256);
                    _strcat(lpszOutput, szFieldText);
                    if (subitem != NUMCOLUMNS - 1)
                        _strcat(lpszOutput, TEXT("\t"));
                }
                _strcat(lpszOutput, TEXT("\r\n"));
                bytesIO = (DWORD)(_strlen(lpszOutput) * sizeof(WCHAR));
                WriteFile(hFile, (LPCVOID)lpszOutput, bytesIO, &bytesIO, NULL);
            }
        }
    }
    __finally {
        if (lpszOutput != NULL)
            supHeapFree(lpszOutput);

        supSetWaitCursor(FALSE);
        ReleaseCapture();
        CloseHandle(hFile);
    }
}

/*
* DmpUIClearEvents
*
* Purpose:
*
* File -> Clear log handler.
*
*/
VOID DmpUIClearEvents(
    VOID
)
{
    ListView_DeleteAllItems(g_ctx.EventList);
    InterlockedExchange((LONG*)&g_uTotalEvents, (LONG)0);

    RtlDestroyHeap(EventListHeap);
    EventListHeap = RtlCreateHeap(HEAP_GROWABLE, NULL, 0, 0, NULL, NULL);

    DmUIUpdateStatusBar();
}

/*
* DmpUISetDefaultSettings
*
* Purpose:
*
* Reset current program settings to default.
*
*/
VOID DmpUISetDefaultSettings(
    VOID
)
{
    RtlSecureZeroMemory(&g_ctx.Settings, sizeof(SETTINGS));
    g_ctx.Settings.AutoScroll = TRUE;
    g_ctx.Settings.CaptureDrivers = TRUE;

    RtlSecureZeroMemory(&g_szOutputDirectory, sizeof(g_szOutputDirectory));
    _strcpy(g_szOutputDirectory, USER_SHARED_DATA->NtSystemRoot);
    _strcat(g_szOutputDirectory, L"\\TEMP\\");

    RtlInitUnicodeString(&g_OutputDirectory, g_szOutputDirectory);
}

/*
* DmUIChangeImageForButton
*
* Purpose:
*
* Set new image for given button.
*
*/
LRESULT DmUIChangeImageForButton(
    _In_ HWND hWndToolbar,
    _In_ INT iButton,
    _In_ INT iImage
)
{
    TBBUTTONINFO tbInfo;

    RtlSecureZeroMemory(&tbInfo, sizeof(tbInfo));
    tbInfo.cbSize = sizeof(TBBUTTONINFO);
    tbInfo.dwMask = TBIF_IMAGE;
    tbInfo.iImage = iImage;
    return SendMessage(hWndToolbar, TB_SETBUTTONINFO,
        (WPARAM)iButton, (LPARAM)&tbInfo);
}

/*
* DmUINotify
*
* Purpose:
*
* Spawn notification dialog.
*
*/
VOID CALLBACK DmUINotify(
    _In_ PVOID lpParameter,
    _In_ BOOLEAN TimerOrWaitFired
)
{
    PDRVMON_PACKET Packet;

    UNREFERENCED_PARAMETER(TimerOrWaitFired);
    UNREFERENCED_PARAMETER(lpParameter);

    //
    // Show filter dialog and wait for user.
    //
    Packet = (PDRVMON_PACKET)g_ctx.SharedMemory;
    RtlSecureZeroMemory(&g_FltPacket, sizeof(DRVMON_PACKET));
    RtlCopyMemory(&g_FltPacket, Packet, sizeof(DRVMON_PACKET));

    DialogBoxParam(g_ctx.hInstance, MAKEINTRESOURCE(IDD_DIALOG_LOADEVENT), g_ctx.MainWindow,
        (DLGPROC)&FilterDialogProc, (LPARAM)&g_FltPacket);

    //
    // Send back to driver.
    //
    Packet->UserAnswer = g_FltPacket.UserAnswer;
    SetEvent(g_ctx.DataBufferCompleteEvent);
}

/*
* DmUIAddChangeOutputDirectoryEvent
*
* Purpose:
*
* Add event with new output directory.
*
*/
VOID DmUIAddChangeOutputDirectoryEvent(
    _In_ LPWSTR NewOutputDirectory,
    _In_ SIZE_T cchDirectory
)
{
    DRVMON_EVENT AppEvent;

    if (cchDirectory > MAX_PATH)
        return;

    RtlSecureZeroMemory(&AppEvent, sizeof(AppEvent));
    GetSystemTimeAsFileTime((LPFILETIME)&AppEvent.LogTime);
    AppEvent.EventType = EVENT_TYPE_INFORMATION;
    _strcpy(AppEvent.wEvent, DM_EVENT_NEW_OUTDIR);
    _strcat(AppEvent.wEvent, NewOutputDirectory);
    DmUIAddEvent(&AppEvent);

}

/*
* DmUIAddSettingsChangeEvent
*
* Purpose:
*
* Add event with new settings state.
*
*/
VOID DmUIAddSettingsChangeEvent(
    _In_ DM_GUI_SETTING Setting,
    _In_ BOOL bEnabled
)
{
    DRVMON_EVENT AppEvent;

    RtlSecureZeroMemory(&AppEvent, sizeof(AppEvent));
    GetSystemTimeAsFileTime((LPFILETIME)&AppEvent.LogTime);
    AppEvent.EventType = EVENT_TYPE_INFORMATION;

    switch (Setting) {

    case UIAutoScrool:

        if (bEnabled)
            _strcpy(AppEvent.wEvent, DM_EVENT_AUTOSCROLL_ON);
        else
            _strcpy(AppEvent.wEvent, DM_EVENT_AUTOSCROLL_OFF);

        break;

    case UICaptureDrivers:
        if (bEnabled)
            _strcpy(AppEvent.wEvent, DM_EVENT_CAPTURE_ON);
        else
            _strcpy(AppEvent.wEvent, DM_EVENT_CAPTURE_OFF);

        break;

    case UIBlockDrivers:

        if (bEnabled)
            _strcpy(AppEvent.wEvent, DM_EVENT_BLOCK_ON);
        else
            _strcpy(AppEvent.wEvent, DM_EVENT_BLOCK_OFF);

        break;
    }
    DmUIAddEvent(&AppEvent);
}

/*
* DmUIAddInitializationCompleteEvent
*
* Purpose:
*
* Add event with state of program initialization.
*
*/
VOID DmUIAddInitializationCompleteEvent(
    _In_ DWORD dwState
)
{
    DRVMON_EVENT AppEvent;

    RtlSecureZeroMemory(&AppEvent, sizeof(AppEvent));
    GetSystemTimeAsFileTime((LPFILETIME)&AppEvent.LogTime);

    if (dwState == ERROR_SUCCESS) {
        AppEvent.EventType = EVENT_TYPE_INFORMATION;
        _strcpy(AppEvent.wEvent, DM_DRIVER_NAME);
        _strcat(AppEvent.wEvent, TEXT(" loaded, output directory "));
        _strcat(AppEvent.wEvent, g_szOutputDirectory);
    }
    else {
        AppEvent.EventType = EVENT_TYPE_APP_ERROR;
        AppEvent.Tag = dwState;
    }
    DmUIAddEvent(&AppEvent);
}

/*
* DmpUIWelcomeEvent
*
* Purpose:
*
* Add welcome event.
*
*/
VOID DmpUIWelcomeEvent(
    VOID
)
{
    DRVMON_EVENT AppEvent;
    RtlSecureZeroMemory(&AppEvent, sizeof(AppEvent));
    GetSystemTimeAsFileTime((LPFILETIME)&AppEvent.LogTime);
    AppEvent.EventType = EVENT_TYPE_INFORMATION;
    _strcpy(AppEvent.wEvent, L"DrvMon v");
    _strcat(AppEvent.wEvent, DM_VERSION);
    DmUIAddEvent(&AppEvent);
}

VOID DmTestEvent(
    VOID
)
{
    DRVMON_EVENT AppEvent;
    RtlSecureZeroMemory(&AppEvent, sizeof(AppEvent));
    GetSystemTimeAsFileTime((LPFILETIME)&AppEvent.LogTime);
    AppEvent.EventType = EVENT_TYPE_DRIVER_LOAD;
    _strcpy(AppEvent.wEvent, L"C:\\windows\\system32\\drivers\\beep.sys");
    DmUIAddEvent(&AppEvent);
}

/*
* DmUIAddEvent
*
* Purpose:
*
* Add event to main window event list.
*
*/
BOOL DmUIAddEvent(
    _In_ PDRVMON_EVENT pEvent
)
{
    BOOL bResult = FALSE;
    INT iImage = 0, index;
    UINT ModuleFileNameOffset = 0;
    SIZE_T sz;

    LPWSTR lpEvent = NULL;
    PDRVMON_EVENT pLoggedEvent = NULL;

    WCHAR szTimeBuffer[100];
    TIME_FIELDS SystemTime;
    LVITEM lvitem;

    WCHAR szTempBuffer[MAX_EVENT_MESSAGE_LENGTH];

    __try {

        /*
        0 0   - error (OIC_ERROR)
        1 102 - drvmon info
        2 103 - denied
        3 104 - loading
        4 105 - error
        5 106 - allowed
        6 0   - error (OIC_ERROR)
        */

        switch (pEvent->EventType) {

        case EVENT_TYPE_DRV_ERROR:
        case EVENT_TYPE_APP_ERROR:
            lpEvent = EVENT_STR_ERROR;
            iImage = 0;
            break;

        case EVENT_TYPE_DRIVER_LOAD:
            lpEvent = EVENT_STR_LOADIMAGE;
            iImage = 3;
            break;

        case EVENT_TYPE_DRIVER_COLLECTED:
            lpEvent = EVENT_STR_COLLECTED;
            iImage = 1;
            break;

        case EVENT_TYPE_DRIVER_PATCHED:
            lpEvent = EVENT_STR_DENIED;
            iImage = 2;
            break;

        case EVENT_TYPE_DRIVER_ALLOWED:
            lpEvent = EVENT_STR_ALLOWED;
            iImage = 5;
            break;

        case EVENT_TYPE_INFORMATION:
            lpEvent = EVENT_INFO;
            iImage = 1;
            break;

        default:
            break;
        }

        switch (pEvent->EventType) {

        case EVENT_TYPE_DRIVER_LOAD:
        case EVENT_TYPE_DRIVER_COLLECTED:
        case EVENT_TYPE_DRIVER_PATCHED:
        case EVENT_TYPE_DRIVER_ALLOWED:

            //
            // Save original event.
            //
            pLoggedEvent = (PDRVMON_EVENT)RtlAllocateHeap(
                EventListHeap,
                HEAP_ZERO_MEMORY,
                sizeof(DRVMON_EVENT));

            if (pLoggedEvent)
                RtlCopyMemory(pLoggedEvent, pEvent, sizeof(DRVMON_EVENT));

            sz = _strlen(pEvent->wEvent);
            if (sz) {
                RtlSecureZeroMemory(szTempBuffer, sizeof(szTempBuffer));
                if (supConvertFileName(szTempBuffer, sz, pEvent->wEvent, MAX_EVENT_MESSAGE_LENGTH))
                    _strcpy(pEvent->wEvent, szTempBuffer);

                ModuleFileNameOffset = supIsNtNamePrefix(pEvent->wEvent, sz * sizeof(WCHAR));
            }
            break;

        case EVENT_TYPE_APP_ERROR:
            //
            // Display error code if submitted, otherwise output event text.
            //
            if (pEvent->Tag != 0) {
                _strcpy(pEvent->wEvent, EVENT_STR_APP_ERROR);
                _strcat(pEvent->wEvent, TEXT(" 0x"));
                ultohex(pEvent->Tag, _strend(pEvent->wEvent));
            }
            break;

        case EVENT_TYPE_DRV_ERROR:
            //
            // Display error code if submitted, otherwise output event text.
            //
            if (pEvent->Tag != 0) {
                _strcpy(pEvent->wEvent, EVENT_STR_DRV_ERROR);
                _strcat(pEvent->wEvent, TEXT(" 0x"));
                ultohex(pEvent->Tag, _strend(pEvent->wEvent));
            }
            break;

        default:
            break;
        }

        //
        // Add event type.
        //
        RtlSecureZeroMemory(&lvitem, sizeof(LV_ITEM));
        lvitem.mask = LVIF_TEXT | LVIF_IMAGE | LVIF_PARAM;
        lvitem.iSubItem = 0;
        lvitem.pszText = lpEvent;
        lvitem.iItem = MAXINT;
        lvitem.iImage = iImage;
        lvitem.lParam = (LPARAM)pLoggedEvent;
        index = ListView_InsertItem(g_ctx.EventList, &lvitem);

        if (index == -1)
            return FALSE;

        InterlockedIncrement((PLONG)&g_uTotalEvents);
        DmUIUpdateStatusBar();

        //
        // Add event time.
        //
        RtlSecureZeroMemory(szTimeBuffer, sizeof(szTimeBuffer));
        RtlSecureZeroMemory(&SystemTime, sizeof(SystemTime));
        FileTimeToLocalFileTime((PFILETIME)&pEvent->LogTime, (PFILETIME)&pEvent->LogTime);
        RtlTimeToTimeFields((PLARGE_INTEGER)&pEvent->LogTime, (PTIME_FIELDS)&SystemTime);

        _snwprintf_s(
            szTimeBuffer,
            99,
            99,
            DM_FORMATTED_TIME_VALUE,
            SystemTime.Hour,
            SystemTime.Minute,
            SystemTime.Second,
            SystemTime.Milliseconds);

        lvitem.mask = LVIF_TEXT;
        lvitem.iSubItem = 1;
        lvitem.pszText = szTimeBuffer;
        lvitem.iItem = index;
        ListView_SetItem(g_ctx.EventList, &lvitem);

        //
        // Add event description.
        //
        lvitem.mask = LVIF_TEXT;
        lvitem.iSubItem = 2;
        lvitem.pszText = &pEvent->wEvent[ModuleFileNameOffset];
        lvitem.iItem = index;
        ListView_SetItem(g_ctx.EventList, &lvitem);

        //
        // Auto scroll if needed.
        //
        if (g_ctx.Settings.AutoScroll != FALSE) {
            ListView_EnsureVisible(g_ctx.EventList, index, 0);
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }

    return bResult;
}

/*
* DmUIUpdateStatusBar
*
* Purpose:
*
* Main window status bar update.
*
*/
VOID DmUIUpdateStatusBar(
    VOID
)
{
    WCHAR szBuffer[100];

    _strcpy(szBuffer, TEXT("Events: "));
    ultostr(g_uTotalEvents, _strend(szBuffer));
    SetWindowText(g_ctx.StatusBar, szBuffer);
}

/*
* DmpMainWindowResizeHandler
*
* Purpose:
*
* Main window WM_SIZE handler.
*
*/
VOID DmpMainWindowResizeHandler(
    VOID
)
{
    RECT ToolBarRect, StatusBarRect;
    LONG posY, sizeY, sizeX;

    SendMessage(g_ctx.ToolBar, WM_SIZE, 0, 0);
    SendMessage(g_ctx.StatusBar, WM_SIZE, 0, 0);

    RtlSecureZeroMemory(&ToolBarRect, sizeof(ToolBarRect));
    RtlSecureZeroMemory(&StatusBarRect, sizeof(StatusBarRect));
    GetWindowRect(g_ctx.ToolBar, &ToolBarRect);
    GetWindowRect(g_ctx.StatusBar, &StatusBarRect);

    sizeY = StatusBarRect.top - ToolBarRect.bottom;
    posY = ToolBarRect.bottom - ToolBarRect.top;
    sizeX = ToolBarRect.right - ToolBarRect.left;
    SetWindowPos(g_ctx.EventList, NULL, 0, posY, sizeX, sizeY, 0);
}

/*
* DmpHandleSubMenu
*
* Purpose:
*
* Event list sub menu handler.
*
*/
VOID DmpHandleSubMenu(
    _In_ HWND hwnd,
    _In_ WPARAM CommandId
)
{
    BOOL bAdded = FALSE;
    ULONG State = 0;
    UINT NtPrefix;
    INT nSelected;
    SIZE_T Length;
    LVITEM lvitem;

    LPWSTR lpFileName, lpEvent;

    UCHAR Hash[SHA256_DIGEST_LENGTH];
    CHAR szHash[SHA256_HASH_STRING_LENGTH + 1];
    WCHAR wszHash[SHA256_HASH_STRING_LENGTH + 1];

    DRVMON_EVENT Event, NewEvent;

    if (ListView_GetSelectedCount(g_ctx.EventList) == 0)
        return;

    nSelected = ListView_GetSelectionMark(g_ctx.EventList);
    if (nSelected < 0)
        return;

    //
    // Query associated event info.
    //
    RtlSecureZeroMemory(&lvitem, sizeof(lvitem));

    lvitem.mask = LVIF_PARAM;
    lvitem.iItem = nSelected;
    if (!ListView_GetItem(g_ctx.EventList, &lvitem))
        return;

    if (lvitem.lParam == 0)
        return;

    RtlSecureZeroMemory(&Event, sizeof(Event));

    __try {
        RtlCopyMemory(&Event, (PVOID)lvitem.lParam, sizeof(DRVMON_EVENT));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return;
    }

    Length = _strlen(Event.wEvent);
    if (Length == 0)
        return;

    NtPrefix = supIsNtNamePrefix(Event.wEvent, Length * sizeof(WCHAR));

    switch (CommandId) {
    case ID_JUMPTO:

        RtlSecureZeroMemory(g_szTempDrvName, sizeof(g_szTempDrvName));
        if (_filepath(&Event.wEvent[NtPrefix], g_szTempDrvName))
            supShellExecuteVerb(hwnd, g_szTempDrvName, NULL, DM_EXPLORE_VERB);
        break;

    case ID_PROPERTIES:

        supShellExecuteVerb(hwnd, &Event.wEvent[NtPrefix], NULL, DM_PROPERTIES_VERB);
        break;

    case ID_SEARCHONLINE_BYHASH:

        RtlSecureZeroMemory(Hash, sizeof(Hash));
        if (supHashFile(&Event.wEvent[NtPrefix], Hash, SHA256_DIGEST_LENGTH, supSha256Buffer)) {

            RtlSecureZeroMemory(szHash, sizeof(szHash));

            if (supPrintHash(
                (PUCHAR)&Hash,
                SHA256_DIGEST_LENGTH,
                (PUCHAR)&szHash,
                SHA256_HASH_STRING_LENGTH,
                FALSE))
            {
                RtlSecureZeroMemory(wszHash, sizeof(wszHash));
                MultiByteToWideChar(CP_ACP, 0, szHash, (INT)_strlen_a(szHash), wszHash, SHA256_HASH_STRING_LENGTH);
                supRunSearchQueryGoogle(hwnd, wszHash, sizeof(wszHash));
            }
        }
        break;

    case ID_SEARCHONLINE_BYNAME:

        lpFileName = _filename(&Event.wEvent[NtPrefix]);
        if (lpFileName) {
            Length = _strlen(lpFileName);
            supRunSearchQueryGoogle(hwnd, lpFileName, Length * sizeof(WCHAR));
        }
        break;

    case ID_INSERTTOWHITELIST:

        lpFileName = &Event.wEvent[NtPrefix];
        Length = _strlen(lpFileName) * sizeof(WCHAR);
        if (Length) {
            RtlSecureZeroMemory(Hash, sizeof(Hash));

            RtlSecureZeroMemory(&NewEvent, sizeof(NewEvent));
            GetSystemTimeAsFileTime((LPFILETIME)&NewEvent.LogTime);
            NewEvent.EventType = EVENT_TYPE_INFORMATION;

            if (supHashFile(lpFileName, Hash, SHA256_DIGEST_LENGTH, supSha256Buffer)) {

                bAdded = (KnownDriversAddEntry(0, ENTRY_FLAGS_DEFAULT, lpFileName, Length,
                    Hash, SHA256_DIGEST_LENGTH, &State) != NULL);

                if (bAdded) {
                    lpEvent = DM_WHITELIST_ADD_OK;
                    bAdded = DmManageWhiteList(TRUE, 0, ENTRY_FLAGS_DEFAULT, lpFileName, Length, Hash, SHA256_DIGEST_LENGTH);
                    if (bAdded == FALSE) {
                        NewEvent.EventType = EVENT_TYPE_DRV_ERROR;
                        lpEvent = DM_ERROR_SEND_REQUEST;
                    }
                }
                else {
                    NewEvent.EventType = EVENT_TYPE_APP_ERROR;
                    if (State == ERROR_ALREADY_EXISTS)
                        lpEvent = DM_WHITELIST_DUPLICATE;
                    else
                        if (State == ERROR_NOT_ENOUGH_MEMORY)
                            lpEvent = DM_ERROR_OUT_OF_MEM;
                        else
                            lpEvent = DM_WHITELIST_ADD_ERROR;
                }

            }
            else {
                lpEvent = DM_ERROR_CALC_HASH;
            }
            _strcpy(NewEvent.wEvent, lpEvent);
            DmUIAddEvent(&NewEvent);
        }
        break;
    }
}

/*
* DmpHandleWMCommand
*
* Purpose:
*
* Main window WM_COMMAND handler.
*
*/
VOID DmpHandleWMCommand(
    _In_ HWND hwnd,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
)
{
    UNREFERENCED_PARAMETER(lParam);

    switch (LOWORD(wParam)) {

    case ID_FILE_SAVELOG:
        DmpSaveLog(hwnd);
        break;

    case ID_FILE_CLEARLOG:
        DmpUIClearEvents();
        break;

    case ID_FILE_EXIT:
        PostQuitMessage(0);
        break;

    case ID_MONITOR_CHANGEOUTPUTDIRECTORY:
        DmpUIChangeOutputDirectory(hwnd);
        break;

    case ID_MONITOR_AUTOSCROLL:
        DmpUIChangeAutoScroll(hwnd);
        break;

    case ID_MONITOR_BLOCKDRIVERLOADING:
        DmpUIChangeBlockDrivers(hwnd);
        break;

    case ID_MONITOR_CAPTUREDRIVERS:
        DmpUIChangeCaptureDrivers(hwnd);
        break;

    case ID_MONITOR_CONFIGURE:
        DialogBoxParam(g_ctx.hInstance, MAKEINTRESOURCE(IDD_DIALOG_CONFIG),
            hwnd, (DLGPROC)&ConfigDialogProc, 0);
        break;

    case ID_MONITOR_MANAGEWHITELIST:
        DialogBoxParam(g_ctx.hInstance, MAKEINTRESOURCE(IDD_DIALOG_WHITELIST),
            hwnd, (DLGPROC)&WhiteListDialogProc, 0);
        break;

    case ID_HELP_MANUAL:
        supShowHelp();
        break;

    case ID_HELP_ABOUT:
        DialogBoxParam(g_ctx.hInstance, MAKEINTRESOURCE(IDD_DIALOG_ABOUT),
            hwnd, (DLGPROC)&AboutDialogProc, 0);
        break;

    case ID_JUMPTO:
    case ID_PROPERTIES:
    case ID_SEARCHONLINE_BYHASH:
    case ID_SEARCHONLINE_BYNAME:
    case ID_INSERTTOWHITELIST:
        DmpHandleSubMenu(hwnd, LOWORD(wParam));
        break;

    default:
        break;
    }

}

/*
* DmpHandleWMNotify
*
* Purpose:
*
* Main window WM_NOTIFY handler.
*
*/
VOID DmpHandleWMNotify(
    _In_ HWND hwnd,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
)
{
    LPNMHDR hdr = (LPNMHDR)lParam;
    LPTOOLTIPTEXT lpttt;
    POINT pt1;
    LVITEM lvitem;

    UNREFERENCED_PARAMETER(wParam);

    if (hdr) {

        if (hdr->hwndFrom == g_ctx.EventList) {

            switch (hdr->code) {

            case NM_SETFOCUS:
                if (ListView_GetSelectionMark(g_ctx.EventList) == -1) {
                    lvitem.mask = LVIF_STATE;
                    lvitem.iItem = 0;
                    lvitem.state = LVIS_SELECTED | LVIS_FOCUSED;
                    lvitem.stateMask = LVIS_SELECTED | LVIS_FOCUSED;
                    ListView_SetItem(g_ctx.EventList, &lvitem);
                }
                break;

            case NM_RCLICK:
                if (GetCursorPos(&pt1)) {
                    TrackPopupMenu(GetSubMenu(g_ctx.hEventListPopupMenu, 0),
                        TPM_RIGHTBUTTON | TPM_LEFTALIGN,
                        pt1.x, pt1.y, 0, hwnd,
                        NULL);
                }
                break;

            default:
                break;
            }

        }

        if (hdr->code == TTN_GETDISPINFO) {
            lpttt = (LPTOOLTIPTEXT)lParam;
            switch (lpttt->hdr.idFrom) {
            case ID_FILE_CLEARLOG:
            case ID_FILE_SAVELOG:
            case ID_MONITOR_AUTOSCROLL:
            case ID_MONITOR_BLOCKDRIVERLOADING:
            case ID_MONITOR_CAPTUREDRIVERS:
                lpttt->hinst = g_ctx.hInstance;
                lpttt->lpszText = MAKEINTRESOURCE(lpttt->hdr.idFrom);
                lpttt->uFlags |= TTF_DI_SETITEM;
                break;

            default:
                break;

            }
        }
    }
}

/*
* DmMainWindowProc
*
* Purpose:
*
* Main window procedure.
*
*/
LRESULT CALLBACK DmMainWindowProc(
    _In_ HWND hwnd,
    _In_ UINT uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
)
{
    switch (uMsg) {

    case WM_COMMAND:
        DmpHandleWMCommand(hwnd, wParam, lParam);
        break;

    case WM_CLOSE:
        PostQuitMessage(0);
        break;

    case WM_SIZE:
        if (!IsIconic(hwnd)) {
            DmpMainWindowResizeHandler();
        }
        break;

    case WM_NOTIFY:
        DmpHandleWMNotify(hwnd, wParam, lParam);
        break;

    case WM_GETMINMAXINFO:
        if (lParam) {
            ((PMINMAXINFO)lParam)->ptMinTrackSize.x = 640;
            ((PMINMAXINFO)lParam)->ptMinTrackSize.y = 480;
        }
        break;

    default:
        break;
    }

    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}


/*
* DmpUILoadImageList
*
* Purpose:
*
* Create and load image list from icon resource type.
*
*/
HIMAGELIST DmpUILoadImageList(
    _In_ HINSTANCE hInstance,
    _In_ UINT FirstId,
    _In_ UINT LastId
)
{
    UINT       i;
    HIMAGELIST list;
    HICON      hIcon;

    list = ImageList_Create(16, 16, ILC_COLOR32 | ILC_MASK, 8, 8);
    if (list) {

        hIcon = LoadImage(NULL, MAKEINTRESOURCE(OIC_ERROR), IMAGE_ICON, 16, 16, LR_SHARED);
        if (hIcon) {
            ImageList_ReplaceIcon(list, -1, hIcon);
            DestroyIcon(hIcon);
        }

        for (i = FirstId; i <= LastId; i++) {
            hIcon = LoadImage(hInstance, MAKEINTRESOURCE(i), IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR);
            if (hIcon) {
                ImageList_ReplaceIcon(list, -1, hIcon);
                DestroyIcon(hIcon);
            }
        }
    }
    return list;
}

/*
* DmShowError
*
* Purpose:
*
* Display detailed last error to user.
*
*/
VOID DmShowError(
    _In_ HWND hWnd,
    _In_ LPWSTR Msg
)
{
    LPWSTR lpMsgBuf = NULL;
    WCHAR szErrorMsg[MAX_PATH * 2];

    if (FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
        NULL, GetLastError(),
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&lpMsgBuf, 0, NULL))
    {
        RtlSecureZeroMemory(&szErrorMsg, sizeof(szErrorMsg));
        _snwprintf_s(szErrorMsg, MAX_PATH * 2, MAX_PATH, TEXT("%ws: %ws"), Msg, lpMsgBuf);
        LocalFree(lpMsgBuf);
        MessageBox(hWnd, szErrorMsg, FULLPROGRAMNAME, MB_OK | MB_ICONERROR);
    }
}

/*
* DmpLoadDriver
*
* Purpose:
*
* Load DrvMon driver and open device handle.
*
*/
DWORD DmpLoadDriver(
    VOID
)
{
    BOOL        bCond = FALSE, bResult = FALSE;
    NTSTATUS    Status = STATUS_UNSUCCESSFUL;
    DWORD       dwResult = ERROR_BAD_DRIVER;
    HANDLE      hDevice = NULL;
    SC_HANDLE   schSCManager = NULL;
    WCHAR       szFile[MAX_PATH * 2];

    do {

        _strcpy(szFile, USER_SHARED_DATA->NtSystemRoot);
        _strcat(szFile, L"\\system32\\drivers\\");
        _strcat(szFile, DM_DRIVER_NAME);

        dwResult = supExtractDriver(szFile);
        if (dwResult != ERROR_SUCCESS)
            break;

        schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
        if (schSCManager) {
            //
            // Unload and remove old driver entry.
            //
            scmStopDriver(schSCManager, DM_DISPLAY_NAME);
            scmRemoveDriver(schSCManager, DM_DISPLAY_NAME);

            //
            // Install new driver entry and load driver.
            //
            scmInstallDriver(schSCManager, DM_DISPLAY_NAME, szFile);
            bResult = scmStartDriver(schSCManager, DM_DISPLAY_NAME);
            if (bResult) {
                hDevice = supOpenDrvMon(DM_DEVICE_NAME, &Status);
                if (hDevice == NULL)
                    dwResult = RtlNtStatusToDosError(Status);
                else
                    g_ctx.hDrvMonDevice = hDevice;
            }
            else {
                dwResult = ERROR_BAD_DRIVER;
            }
            CloseServiceHandle(schSCManager);
        }


    } while (bCond);

    return dwResult;
}

/*
* DmpUnloadDriver
*
* Purpose:
*
* Close device handle and unload drvmon.
*
*/
VOID DmpUnloadDriver(
    VOID
)
{
    if (g_ctx.hDrvMonDevice) {
        NtClose(g_ctx.hDrvMonDevice);
        g_ctx.hDrvMonDevice = NULL;
    }
    scmUnloadDeviceDriver(DM_DISPLAY_NAME);
}

/*
* DmpUIWriteSettings
*
* Purpose:
*
* Write current program settings to registry available.
*
*/
VOID DmpUIWriteSettings(
    VOID
)
{
    DWORD cbData;
    HKEY hKey = NULL;
    LRESULT lResult;

    lResult = RegCreateKeyEx(HKEY_CURRENT_USER,
        DM_SETTINGS_KEY,
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        MAXIMUM_ALLOWED,
        NULL,
        &hKey,
        NULL);

    if (lResult != ERROR_SUCCESS) {
        DmShowError(GetDesktopWindow(), DM_ERROR_SETTINGS_SAVE);
        return;
    }

    //
    // Write settings.
    //
    cbData = sizeof(SETTINGS);
    lResult = RegSetValueEx(hKey,
        DM_SETTINGS_VALUE,
        0,
        REG_BINARY,
        (BYTE*)&g_ctx.Settings, cbData);

    if (lResult != ERROR_SUCCESS) {
        DmShowError(GetDesktopWindow(), DM_ERROR_SETTINGS_SAVE);
    }

    //
    // Write output directory.
    //
    cbData = (DWORD)((1 + _strlen(g_szOutputDirectory)) * sizeof(WCHAR));
    lResult = RegSetValueEx(hKey,
        DM_SETTING_OUTDIR,
        0,
        REG_SZ,
        (BYTE*)&g_szOutputDirectory, cbData);

    if (lResult != ERROR_SUCCESS) {
        DmShowError(GetDesktopWindow(), DM_ERROR_SETTINGS_SAVE);
    }

    //
    // Write whitelist data to registry.
    //
    supWriteWhiteList(hKey);

    RegCloseKey(hKey);
}

/*
* DmpUIReadSettings
*
* Purpose:
*
* Read current program settings from registry if available.
*
*/
VOID DmpUIReadSettings(
    VOID
)
{
    DWORD cbData;
    HKEY hKey = NULL;
    LRESULT lResult;
    SETTINGS tmp;

    //
    //  Open key.
    //
    lResult = RegOpenKeyEx(HKEY_CURRENT_USER,
        DM_SETTINGS_KEY,
        REG_OPTION_NON_VOLATILE,
        MAXIMUM_ALLOWED,
        &hKey);

    if (lResult != ERROR_SUCCESS)
        return;

    RtlSecureZeroMemory(&tmp, sizeof(tmp));

    //
    // Query settings.
    //
    cbData = sizeof(SETTINGS);
    lResult = RegQueryValueEx(hKey,
        DM_SETTINGS_VALUE,
        NULL,
        NULL,
        (LPBYTE)&tmp,
        &cbData);

    if (lResult == ERROR_SUCCESS) {
        //
        // Copy from temp variable to g_ctx.
        //
        RtlCopyMemory(&g_ctx.Settings, &tmp, sizeof(SETTINGS));
    }

    //
    // Query output directory.
    //
    cbData = 0;
    lResult = RegQueryValueEx(hKey,
        DM_SETTING_OUTDIR,
        NULL,
        NULL,
        NULL,
        &cbData);
    if (lResult == ERROR_SUCCESS) {
        if (cbData <= (MAX_PATH * sizeof(WCHAR))) {

            lResult = RegQueryValueEx(hKey,
                DM_SETTING_OUTDIR,
                NULL,
                NULL,
                (LPBYTE)&g_szOutputDirectory,
                &cbData);

            if (lResult == ERROR_SUCCESS)
                RtlInitUnicodeString(&g_OutputDirectory, g_szOutputDirectory);
        }
    }

    //
    // Always add VGA.DLL to whitelist on systems below Windows 8.
    //
    if (g_ctx.osver.dwBuildNumber < 9200)
        supWhiteListLegacyAddVgaEntry();

    //
    // Read whitelist from registry.
    //
    supReadWhiteList(hKey);

//#ifdef _DEBUG
//    supxxxTestKD();
//#endif

    RegCloseKey(hKey);
}

/*
* DmpUIApplySettings
*
* Purpose:
*
* Apply current program settings.
* This routine inform driver about flags, output directory and whitelist data.
*
*/
VOID DmpUIApplySettings(
    _In_ HWND hWnd
)
{
    DWORD dwStyle;

    //
    // Set output directory.
    //
    DmSetOutputDirectory(&g_OutputDirectory);

    //
    // Inform driver about whitelist.
    //
    KnownDriversInformDriver();

    //
    // Set internal flags.
    //      
    if (g_ctx.Settings.BlockDrivers)
        g_ctx.DrvMonFlags |= DRVMON_BLOCK_DRIVERS_LOADING;

    if (g_ctx.Settings.CaptureDrivers)
        g_ctx.DrvMonFlags |= DRVMON_CAPTURE_DRIVERS;

    if (g_ctx.Settings.ManualConfirmDriverLoading)
        g_ctx.DrvMonFlags |= DRVMON_FILTER_ENABLED;

    DmSetInternalFlags(g_ctx.DrvMonFlags);

    //
    // Set GUI.
    //
    dwStyle = ListView_GetExtendedListViewStyle(g_ctx.EventList);

    if (g_ctx.Settings.ShowGridLines)
        dwStyle |= LVS_EX_GRIDLINES;
    else
        dwStyle &= ~LVS_EX_GRIDLINES;

    ListView_SetExtendedListViewStyle(g_ctx.EventList,
        (WPARAM)dwStyle);

    CheckMenuItem(GetMenu(hWnd), ID_MONITOR_AUTOSCROLL, (g_ctx.Settings.AutoScroll != FALSE) ?
        MF_BYCOMMAND | MF_CHECKED : MF_BYCOMMAND | MF_UNCHECKED);

    DmUIChangeImageForButton(g_ctx.ToolBar,
        ID_MONITOR_AUTOSCROLL,
        (g_ctx.Settings.AutoScroll != FALSE) ? IDX_AUTOSCROLLBUTTON_ENABLE : IDX_AUTOSCROLLBUTTON_DISABLE);

    CheckMenuItem(GetMenu(hWnd), ID_MONITOR_CAPTUREDRIVERS, (g_ctx.Settings.CaptureDrivers != FALSE) ?
        MF_BYCOMMAND | MF_CHECKED : MF_BYCOMMAND | MF_UNCHECKED);

    DmUIChangeImageForButton(g_ctx.ToolBar,
        ID_MONITOR_CAPTUREDRIVERS,
        (g_ctx.Settings.CaptureDrivers != FALSE) ? IDX_CAPTUREBUTTON_ENABLE : IDX_CAPTUREBUTTON_DISABLE);

    CheckMenuItem(GetMenu(hWnd), ID_MONITOR_BLOCKDRIVERLOADING, (g_ctx.Settings.BlockDrivers != FALSE) ?
        MF_BYCOMMAND | MF_CHECKED : MF_BYCOMMAND | MF_UNCHECKED);

    DmUIChangeImageForButton(g_ctx.ToolBar,
        ID_MONITOR_BLOCKDRIVERLOADING,
        (g_ctx.Settings.BlockDrivers != FALSE) ? IDX_BLOCKBUTTON_ENABLE : IDX_BLOCKBUTTON_DISABLE);

}

/*
* DmUIMain
*
* Purpose:
*
* Create main window subwindows components.
*
*/
VOID DmUIMain(
    VOID
)
{
    BOOL                    bCond = FALSE, rv = TRUE;
    MSG                     msg1;
    WNDCLASSEX              wincls;
    ATOM                    class_atom = 0;
    DWORD                   dwResult;
    LVCOLUMN                col;
    HMODULE                 hNtdll;
    INITCOMMONCONTROLSEX    icc;

    do {

        //
        // Initialize logger subsystem.
        //
        if (!LoggerInit())
            break;

        EventListHeap = RtlCreateHeap(HEAP_GROWABLE, NULL, 0, 0, NULL, NULL);
        if (EventListHeap == NULL)
            break;

        RtlSetHeapInformation(EventListHeap, HeapEnableTerminationOnCorruption, NULL, 0);

#ifdef _DEBUG
        supxxxTestHash();
#endif

        hNtdll = GetModuleHandle(L"ntdll.dll");
        if (hNtdll)
            _snwprintf_s = (fnptr_snwprintf_s)GetProcAddress(hNtdll, "_snwprintf_s");

        if (_snwprintf_s == NULL)
            break;


        if (!SUCCEEDED(CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE)))
            break;

        //
        // Init common controls library.
        //
        icc.dwSize = sizeof(icc);
        icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_TREEVIEW_CLASSES | ICC_BAR_CLASSES | ICC_TAB_CLASSES;
        if (!InitCommonControlsEx(&icc))
            break;

        //
        // Create main window and it components.
        //
        wincls.cbSize = sizeof(WNDCLASSEX);
        wincls.style = 0;
        wincls.lpfnWndProc = &DmMainWindowProc;
        wincls.cbClsExtra = 0;
        wincls.cbWndExtra = 0;
        wincls.hInstance = g_ctx.hInstance;
        wincls.hIcon = (HICON)LoadImage(g_ctx.hInstance, MAKEINTRESOURCE(IDI_ICON_MAIN), IMAGE_ICON, 0, 0, LR_SHARED);
        wincls.hCursor = (HCURSOR)LoadImage(NULL, MAKEINTRESOURCE(OCR_SIZEWE), IMAGE_CURSOR, 0, 0, LR_SHARED);
        wincls.hbrBackground = NULL;
        wincls.lpszMenuName = MAKEINTRESOURCE(IDR_MENU1);
        wincls.lpszClassName = MAINWINDOWCLASSNAME;
        wincls.hIconSm = 0;

        class_atom = RegisterClassEx(&wincls);
        if (class_atom == 0)
            break;

        g_ctx.MainWindow = CreateWindowEx(0, MAKEINTATOM(class_atom), FULLPROGRAMNAME,
            WS_VISIBLE | WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 800, 600, NULL, NULL, g_ctx.hInstance, NULL);
        if (g_ctx.MainWindow == NULL)
            break;

        g_ctx.StatusBar = CreateWindowEx(0, STATUSCLASSNAME, NULL,
            WS_VISIBLE | WS_CHILD, 0, 0, 0, 0, g_ctx.MainWindow, NULL, g_ctx.hInstance, NULL);
        if (g_ctx.StatusBar == NULL)
            break;

        g_ctx.EventList = CreateWindowEx(WS_EX_CLIENTEDGE, WC_LISTVIEW, NULL,
            WS_VISIBLE | WS_CHILD | WS_TABSTOP | LVS_AUTOARRANGE | LVS_REPORT |
            LVS_SHOWSELALWAYS | LVS_SINGLESEL | LVS_SHAREIMAGELISTS, 0, 0, 0, 0,
            g_ctx.MainWindow, (HMENU)0, g_ctx.hInstance, NULL);
        if (g_ctx.EventList == NULL)
            break;

        g_ctx.hEventListPopupMenu = LoadMenu(g_ctx.hInstance, MAKEINTRESOURCE(IDR_MENU2));
        if (g_ctx.hEventListPopupMenu) {
            SetMenu(g_ctx.EventList, GetSubMenu(g_ctx.hEventListPopupMenu, 0));
        }

        g_ctx.ToolBar = CreateWindowEx(0, TOOLBARCLASSNAME, NULL,
            WS_VISIBLE | WS_CHILD | CCS_TOP | TBSTYLE_FLAT | TBSTYLE_TRANSPARENT |
            TBSTYLE_TOOLTIPS, 0, 0, 0, 0, g_ctx.MainWindow, (HMENU)0, g_ctx.hInstance, NULL);
        if (g_ctx.ToolBar == NULL)
            break;

        // initialization of views
        ListView_SetExtendedListViewStyle(g_ctx.EventList,
            LVS_EX_FULLROWSELECT | LVS_EX_LABELTIP | LVS_EX_DOUBLEBUFFER);

        SetWindowTheme(g_ctx.EventList, TEXT("Explorer"), NULL);

        // set image list
        g_ctx.EventImageList = DmpUILoadImageList(g_ctx.hInstance, IDI_ICON2, IDI_ICON6);
        if (g_ctx.EventImageList) {
            ListView_SetImageList(g_ctx.EventList, g_ctx.EventImageList, LVSIL_SMALL);
        }

        //load toolbar images
        g_ctx.ToolBarMenuImages = ImageList_LoadImage(g_ctx.hInstance, MAKEINTRESOURCE(IDB_BITMAP1),
            16, 7, CLR_DEFAULT, IMAGE_BITMAP, LR_CREATEDIBSECTION);
        if (g_ctx.ToolBarMenuImages) {
            supCreateToolbarButtons(g_ctx.ToolBar, g_ctx.ToolBarMenuImages);
        }

        g_ctx.AccTable = LoadAccelerators(g_ctx.hInstance, MAKEINTRESOURCE(IDR_ACCELERATOR1));

        //create EventList columns
        RtlSecureZeroMemory(&col, sizeof(col));
        col.mask = LVCF_TEXT | LVCF_SUBITEM | LVCF_FMT | LVCF_WIDTH | LVCF_ORDER;
        col.iSubItem = 1;
        col.pszText = LV_EVENT;
        col.fmt = LVCFMT_LEFT;
        col.iOrder = 0;
        col.iImage = I_IMAGENONE;
        col.cx = 100;
        ListView_InsertColumn(g_ctx.EventList, 1, &col);

        col.iSubItem = 2;
        col.pszText = LV_TIME;
        col.iOrder = 1;
        col.cx = 100;
        ListView_InsertColumn(g_ctx.EventList, 2, &col);

        col.iSubItem = 3;
        col.pszText = LV_DESC;
        col.iOrder = 2;
        col.cx = 400;
        ListView_InsertColumn(g_ctx.EventList, 3, &col);

        //
        // Set default settings.
        // 
        DmpUISetDefaultSettings();

        //
        // Read settings if available from registry.
        //
        DmpUIReadSettings();

        //
        // Load driver and set current process.
        //
//#ifdef _DEBUG
//        dwResult = 0;
//#else   
        dwResult = DmpLoadDriver();
//#endif
        //
        // Apply settings, including white list.
        //
        DmpUIApplySettings(g_ctx.MainWindow);

        //
        // Welcome event.
        //
        DmpUIWelcomeEvent();

        //
        // Output initial state event.
        //
        DmUIAddInitializationCompleteEvent(dwResult);

//#ifdef _DEBUG
//        DmTestEvent();
//        DmxxxTestVerify();
//#endif

        //
        // Do focus on listview.
        //
        SendMessage(g_ctx.MainWindow, WM_SIZE, 0, 0);
        SetFocus(g_ctx.EventList);

        do {
            rv = GetMessage(&msg1, NULL, 0, 0);

            if (rv == -1)
                break;

            if (IsDialogMessage(g_ctx.MainWindow, &msg1)) {
                TranslateAccelerator(g_ctx.MainWindow, g_ctx.AccTable, &msg1);
                continue;
            }

            TranslateMessage(&msg1);
            DispatchMessage(&msg1);
        } while (rv != 0);

    } while (bCond);

    //
    // Unload drvmon at program shutdown.
    //
    DmpUnloadDriver();

    //
    // Save current program settings to registry.
    //
    DmpUIWriteSettings();

    if (class_atom != 0)
        UnregisterClass(MAKEINTATOM(class_atom), g_ctx.hInstance);
}
