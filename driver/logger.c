/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2010 - 2017
*
*  TITLE:       LOGGER.C
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
#include "drvmon.h"

HANDLE hLogPipe = NULL;
KMUTEX LogMutex;

VOID LogInit(
    VOID
)
{
    KeInitializeMutex(&LogMutex, 0);
}

VOID LogClose(
    VOID
)
{
    KeWaitForMutexObject(&LogMutex, Executive, KernelMode, FALSE, NULL);
    if (hLogPipe != NULL) {
        ZwClose(hLogPipe);
        hLogPipe = NULL;
    }
    KeReleaseMutex(&LogMutex, FALSE);
}

NTSTATUS LogOpenPipe(
    VOID
)
{
    OBJECT_ATTRIBUTES ObjAttr;
    IO_STATUS_BLOCK IoStatusBlock;
    UNICODE_STRING usPipeName;
    NTSTATUS Status;

    RtlInitUnicodeString(&usPipeName, L"\\Device\\NamedPipe\\" LOG_PIPE_NAME);

    InitializeObjectAttributes(&ObjAttr, &usPipeName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    KeWaitForMutexObject(&LogMutex, Executive, KernelMode, FALSE, NULL);

    Status = ZwCreateFile(
        &hLogPipe,
        FILE_WRITE_DATA | SYNCHRONIZE,
        &ObjAttr,
        &IoStatusBlock,
        0,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );

#ifdef VERBOSE
    if (!NT_SUCCESS(Status)) {
        DbgPrint("Error opening pipe, status: 0x%.8x\n", Status);
    }
#endif

    KeReleaseMutex(&LogMutex, FALSE);
    return Status;
}

VOID LogEvent(
    ULONG EventType,
    PWCHAR lpszEventMsg,
    ULONG Tag
)
{
    ULONG uLength;
    SIZE_T Length;
    IO_STATUS_BLOCK IoStatusBlock;
    DRVMON_EVENT Event;

    if (KeGetCurrentIrql() == PASSIVE_LEVEL) {

        KeWaitForMutexObject(&LogMutex, Executive, KernelMode, FALSE, NULL);
        if (hLogPipe != NULL) {

            RtlSecureZeroMemory(&Event, sizeof(Event));
            Event.EventType = EventType;

            //copy event message
            if (EventType != EVENT_TYPE_DRV_ERROR) {
                if (lpszEventMsg != NULL) {

                    Length = _strlen_w(lpszEventMsg);
                    if (Length > MAX_PATH_DRV) {
                        Length = MAX_PATH_DRV;
                    }
                    _strncpy_w(Event.wEvent, MAX_PATH_DRV, lpszEventMsg, Length);

#ifdef VERBOSE
                    DbgPrint("[DM] Event.wEvent %wS", Event.wEvent);
#endif

                }
            }
            else {
                //otherwise copy error code to be send to user mode
                Event.Tag = Tag;
            }

            //set event time
            KeQuerySystemTime(&Event.LogTime);

            //first send size of passing structure
            uLength = sizeof(DRVMON_EVENT);
            ZwWriteFile(hLogPipe, 0, NULL, NULL, &IoStatusBlock, (PVOID)&uLength, sizeof(uLength), NULL, NULL);

            //second send structure itself
            ZwWriteFile(hLogPipe, 0, NULL, NULL, &IoStatusBlock, &Event, uLength, NULL, NULL);
        }
        KeReleaseMutex(&LogMutex, FALSE);
    }
}
