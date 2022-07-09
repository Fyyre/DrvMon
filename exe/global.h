/*******************************************************************************
*
*  (C) COPYRIGHT Fyyre & EP_X0FF, 2010 - 2017
*
*  TITLE:       GLOBAL.H
*
*  VERSION:     3.00
*
*  DATE:        10 Apr 2017
*
*  Common header file.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

#define OEMRESOURCE

#if !defined UNICODE
#error ANSI build is not supported
#endif

#if (_MSC_VER >= 1900) 
#ifdef _DEBUG
#pragma comment(lib, "vcruntimed.lib")
#pragma comment(lib, "ucrtd.lib")
#else
#pragma comment(lib, "libvcruntime.lib")
#endif
#endif

#pragma comment(lib, "comctl32.lib")

//
// Ignored warnings
//
#pragma warning(disable: 4005) // macro redefinition
#pragma warning(disable: 4201) // nonstandard extension used : nameless struct/union
#pragma warning(disable: 6102) // Using %s from failed function call at line %u
#pragma warning(disable: 6320) // Exception-filter expression is the constant EXCEPTION_EXECUTE_HANDLER
#if (_MSC_VER >= 1900)
#pragma warning(disable: 4091) // 'typedef ': ignored on left of '' when no variable is declared
#pragma warning(disable: 4311) // 'type cast': pointer truncation from %s to %s
#pragma warning(disable: 4312) // 'type cast': conversion from %s to %s of greater size
#endif

#include <Windows.h>
#include <commctrl.h>
#include <ntstatus.h>
#include <ShlObj.h>
#include "consts.h"
#include "..\\shared\\ntos.h"
#include "list.h"
#include "..\\shared\\minirtl\\minirtl.h"
#include "..\\shared\\minirtl\\_filename.h"
#include "..\\shared\\minirtl\\cmdline.h"
#include "..\\shared\\sha256\\sha256.h"
#include "resource.h"

#define EVENT_TYPE_DRV_ERROR            0
#define EVENT_TYPE_DRIVER_LOAD          1
#define EVENT_TYPE_DRIVER_COLLECTED     2
#define EVENT_TYPE_DRIVER_PATCHED       3
#define EVENT_TYPE_DRIVER_ALLOWED       4
#define EVENT_TYPE_INFORMATION          5
#define EVENT_TYPE_APP_ERROR            6

#define MSG_BUFF_SIZE                   0x1000
#define BUFFER_SIZE                     0x1000

#define SHARED_SPACE_SIZE               256 * 1024
#define MAX_PATH_DRV                    MAX_PATH

// DRVMON INTERNAL FLAGS
#define DRVMON_BLOCK_DRIVERS_LOADING    (0x00000002)
#define DRVMON_CAPTURE_DRIVERS          (0x00000004)
#define DRVMON_FILTER_ENABLED           (0x00000008)

#define IOCTL_DRVMON_SETOUTPUT_DIRECTORY    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0901, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_DRVMON_SET_FLAGS              CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0902, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_DRVMON_ADDWLENTRY             CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0903, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_DRVMON_REMOVEWLENTRY          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0904, METHOD_NEITHER, FILE_ANY_ACCESS)

typedef struct DM_HASH_CONTEXT {
    ULONG Total[2];
    ULONG State[8];
    UCHAR Buffer[64];
} DM_HASH_CONTEXT, *PDM_HASH_CONTEXT;

typedef struct _DM_SET_FLAG {
    ULONG cb; //structure self size
    ULONG DrvMonFlag;
} DM_SET_FLAG, *PDM_SET_FLAG;

typedef struct _DM_SET_OUTDIR {
    ULONG cb; //structure self size
    UNICODE_STRING usOutputDirectory;
} DM_SET_OUTDIR, *PDM_SET_OUTDIR;

typedef struct _DM_WL_PACKET {
    ULONG cb; //structure self size
    ULONG_PTR Tag;
    ULONG_PTR Flags;
    UCHAR Hash[SHA256_DIGEST_LENGTH];
    WCHAR DriverName[MAX_PATH + 1];
} DM_WL_PACKET, *PDM_WL_PACKET;

#include "sup.h"
#include "instdrv.h"
#include "gui.h"
#include "excepth.h"
#include "logger.h"
#include "whitelist.h"
#include "aboudDlg.h"
#include "configDlg.h"
#include "whitelistDlg.h"
#include "filterDlg.h"
#include "verify.h"

typedef struct _DRVMONCONTEXT {
    ULONG DrvMonFlags;
    HINSTANCE hInstance;
    HWND MainWindow;
    HWND StatusBar;
    HWND EventList;
    HWND ToolBar;
    HMENU hEventListPopupMenu;
    HIMAGELIST EventImageList;
    HIMAGELIST ToolBarMenuImages;
    HACCEL AccTable;
    PVOID dmHeap;
    HANDLE hDrvMonDevice;
    HANDLE hNotifyWait;
    HANDLE hMemorySection;
    HANDLE DataBufferReadyEvent;
    HANDLE DataBufferCompleteEvent;
    PVOID SharedMemory;

    SETTINGS Settings;
    OSVERSIONINFO osver;
} DRVMONCONTEXT, *PDRVMONCONTEXT;

extern DRVMONCONTEXT g_ctx;
extern UNICODE_STRING g_OutputDirectory;
extern WCHAR g_szOutputDirectory[MAX_PATH * 2];
extern WCHAR g_szTempDrvName[MAX_EVENT_DRIVER_NAME_LENGTH];
