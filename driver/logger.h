/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2010 - 2017
*
*  TITLE:       LOGGER.H
*
*  VERSION:     3.00
*
*  DATE:        31 Mar 2017
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

#define LOG_PIPE_NAME L"DrvMonPipe"

#define EVENT_TYPE_DRV_ERROR          0
#define EVENT_TYPE_DRIVER_LOAD        1
#define EVENT_TYPE_DRIVER_COLLECTED   2
#define EVENT_TYPE_DRIVER_PATCHED     3
#define EVENT_TYPE_DRIVER_ALLOWED     4

NTSTATUS LogOpenPipe(VOID);
VOID LogInit(VOID);
VOID LogClose(VOID);
VOID LogEvent(ULONG EventType, PWCHAR lpszEventMsg, ULONG Tag);

#pragma pack(push, 1)

/* do not change */ 
typedef struct _DRVMON_EVENT {

    ULONG EventType;
    ULONG Tag;
    LARGE_INTEGER LogTime;
    WCHAR wEvent[MAX_PATH_DRV];

} DRVMON_EVENT, *PDRVMON_EVENT;

#pragma pack(pop)