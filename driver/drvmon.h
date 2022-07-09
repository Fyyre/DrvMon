/*******************************************************************************
*
*  (C) COPYRIGHT hfiref0x & Fyyre, 2010 - 2017
*
*  TITLE:       DRVMON.H
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
#pragma once
#pragma warning(disable: 6102) //"Using %s from failed call at line %s"
#pragma warning(disable: 6320) // exception-filter expression is the constant EXCEPTION_EXECUTE_HANDLER

#include <ntifs.h>
#include <Ntstrsafe.h>
#include <intrin.h>

NTKERNELAPI
NTSTATUS
ObReferenceObjectByName(
    __in PUNICODE_STRING ObjectName,
    __in ULONG Attributes,
    __in_opt PACCESS_STATE AccessState,
    __in_opt ACCESS_MASK DesiredAccess,
    __in POBJECT_TYPE ObjectType,
    __in KPROCESSOR_MODE AccessMode,
    __inout_opt PVOID ParseContext,
    __out PVOID *Object);

NTKERNELAPI
PIMAGE_NT_HEADERS
NTAPI
RtlImageNtHeader(
    PVOID Base);

#define ABSOLUTE_TIME(wait) (wait)
#define RELATIVE_TIME(wait) (-(wait))
#define NANOSECONDS(nanos)      \
    (((signed __int64)(nanos)) / 100L)
#define MICROSECONDS(micros)    \
    (((signed __int64)(micros)) * NANOSECONDS(1000L))
#define MILLISECONDS(milli)     \
    (((signed __int64)(milli)) * MICROSECONDS(1000L))
#define SECONDS(seconds)        \
    (((signed __int64)(seconds)) * MILLISECONDS(1000L))

#define TAG_DRVMON_ENTRY ('MvrD')

#define FILE_READ_ACCESS        ( 0x0001 )    // file & pipe
#define FILE_WRITE_ACCESS       ( 0x0002 )    // file & pipe
#define Event1Name              L"\\BaseNamedObjects\\SendaiDataReadyEvent"
#define Event2Name              L"\\BaseNamedObjects\\SendaiDataCompleteEvent"
#define SharedSectionName       L"\\BaseNamedObjects\\SendaiSharedSection"
#define UnknownDrv              L"Unknown"

#define DRVMON_DEV_OBJECT       L"\\Device\\Sendai"

// DRVMON INTERNAL FLAGS 
#define DRVMON_BLOCK_DRIVERS_LOADING  (0x00000002)
#define DRVMON_CAPTURE_DRIVERS        (0x00000004)
#define DRVMON_FILTER_ENABLED         (0x00000008)

#define PACKET_FLAGS_DRIVER_WHITELISTED (0x00000002)

//FILTER consts
#define DRVMON_IDYES                    6
#define DRVMON_IDNO                     7

//IOCTL's
#define IOCTL_DRVMON_SETOUTPUT_DIRECTORY    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0901, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_DRVMON_SET_FLAGS              CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0902, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_DRVMON_ADDWLENTRY             CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0903, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_DRVMON_REMOVEWLENTRY          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0904, METHOD_NEITHER, FILE_ANY_ACCESS)

#define MAX_PATH_DRV                    0x00000104
#define MAXDRIVERNAME                   65535
#define SHARED_SPACE_SIZE               256 * 1024
#define MAX_OUTPUT_DIR_BUFFER_LENGTH    MAX_PATH_DRV * 2

#define DM_MAXIMUM_INPUT_SIZE           640       

#define CHAR_BIT 8
#define MAX_UNICODE_STRING_MAXLENGTH  ((~((~(SIZE_T)0) << (RTL_FIELD_SIZE(UNICODE_STRING, Length) * CHAR_BIT))) & ~(sizeof(((PCUNICODE_STRING)0)->Buffer[0]) - 1))

#include "..\\shared\\minirtl\\minirtl.h"
#include "..\\shared\\sha256\\sha256.h"

/* drvmon client context */
typedef struct _DRVMONCONTEXT {
    ULONG uFlags;
    PEPROCESS DrvMonProcess;
    PKEVENT DataBufferReadyEvent;
    PKEVENT DataBufferCompleteEvent;
    PVOID SharedMemory;
    LPWSTR lpszLog;

    //KSPIN_LOCK SharedMemorySpinLock;
    KMUTEX LogMutex;
    KMUTEX OutputDirectoryMutex;

    BOOLEAN IsShutdown;
    BOOLEAN ProcessNotifyInstalled;
    BOOLEAN ImageNotifyInstalled;

    WCHAR OutputDirectory[MAX_OUTPUT_DIR_BUFFER_LENGTH];
} DRVMONCONTEXT, *PDRVMONCONTEXT;

typedef struct _DRVMON_PACKET {
    ULONG Flags;
    ULONG UserAnswer;
    WCHAR DriverName[MAXDRIVERNAME];
} DRVMON_PACKET, *PDRVMON_PACKET;

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
    WCHAR DriverName[MAX_PATH_DRV + 1];
} DM_WL_PACKET, *PDM_WL_PACKET;

#define mmalloc(l, x) ExAllocatePoolWithTag(l, x, TAG_DRVMON_ENTRY)
#define mmfree(x) ExFreePoolWithTag(x, TAG_DRVMON_ENTRY)

#define LOCK_DATA(LockMutex) KeWaitForSingleObject(LockMutex, Executive, KernelMode, FALSE, NULL)
#define UNLOCK_DATA(LockMutex) KeReleaseMutex(LockMutex, FALSE)

#include "main.h"
#include "sup.h"
#include "logger.h"
#include "whitelist.h"
#include "ntimage.h"
