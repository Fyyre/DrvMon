/*******************************************************************************
*
*  (C) COPYRIGHT Fyyre & EP_X0FF, 2010 - 2017
*
*  TITLE:       GUI.H
*
*  VERSION:     3.00
*
*  DATE:        10 Apr 2017
*
*  Common header file for program GUI routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

#define IDX_SAVEBUTTON                  0
#define IDX_AUTOSCROLLBUTTON_DISABLE    1
#define IDX_AUTOSCROLLBUTTON_ENABLE     2
#define IDX_CLEANBUTTON                 3
#define IDX_BLOCKBUTTON_ENABLE          5
#define IDX_BLOCKBUTTON_DISABLE         6
#define IDX_CAPTUREBUTTON_DISABLE       7
#define IDX_CAPTUREBUTTON_ENABLE        8

typedef enum _DM_GUI_SETTING {
    UIAutoScrool = 0,
    UICaptureDrivers,
    UIBlockDrivers
} DM_GUI_SETTING;

// Maximum length for list view item text
#define MAXITEMLENGTH 0x1000

// Number of columns in main list view
#define NUMCOLUMNS 3

#define MAX_EVENT_MESSAGE_LENGTH     MAX_PATH *4
#define MAX_EVENT_DRIVER_NAME_LENGTH 65535

#pragma pack(push, 1)
typedef struct _DRVMON_EVENT {
    ULONG EventType;
    ULONG Tag;
    LARGE_INTEGER LogTime;
    WCHAR wEvent[MAX_EVENT_MESSAGE_LENGTH];
} DRVMON_EVENT, *PDRVMON_EVENT;

//packet to be sent shared with UM/KM
typedef struct _DRVMON_PACKET {
    ULONG Flags;
    ULONG UserAnswer;
    WCHAR DriverName[MAX_EVENT_DRIVER_NAME_LENGTH];
} DRVMON_PACKET, *PDRVMON_PACKET;

typedef struct _SETTINGS {
    BOOLEAN ShowGridLines;
    BOOLEAN AutoScroll;
    BOOLEAN CaptureDrivers;
    BOOLEAN BlockDrivers;
    BOOLEAN ManualConfirmDriverLoading;
    BOOLEAN Reserved1;
    BOOLEAN Reserved2;
    BOOLEAN Reserved3;
} SETTINGS, *PSETTINGS;
#pragma pack(pop)

VOID CALLBACK DmUINotify(
    _In_ PVOID lpParameter,
    _In_ BOOLEAN TimerOrWaitFired);

BOOL DmUIAddEvent(
    _In_ PDRVMON_EVENT pEvent);

VOID DmUIAddChangeOutputDirectoryEvent(
    _In_ LPWSTR NewOutputDirectory,
    _In_ SIZE_T cchDirectory);

VOID DmUIAddSettingsChangeEvent(
    _In_ DM_GUI_SETTING Setting,
    _In_ BOOL bEnabled);

VOID DmUIAddInitializationCompleteEvent(
    _In_ DWORD dwState);

VOID DmUIMain(
    VOID);

LRESULT DmUIChangeImageForButton(
    _In_ HWND hWndToolbar,
    _In_ INT iButton,
    _In_ INT iImage);

VOID DmUIUpdateStatusBar(
    VOID);

VOID DmShowError(
    _In_ HWND hWnd,
    _In_ LPWSTR Msg);

//fuck you Microsoft, and especially Visual Studio dev team with your strsafe shit.
typedef int(__cdecl *fnptr_snwprintf_s)(
    wchar_t *buffer,
    size_t sizeOfBuffer,
    size_t count,
    const wchar_t *format,
    ...
    );

extern DRVMON_PACKET g_FltPacket;
extern BOOL g_DrvFltInProgress;
extern INT g_SelectedDriverIndex;
