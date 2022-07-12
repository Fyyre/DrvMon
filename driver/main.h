/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2010 - 2017
*
*  TITLE:       MAIN.H
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

_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH DevioctlDispatch;
_Dispatch_type_(IRP_MJ_CREATE)
DRIVER_DISPATCH CreateDispatch;
_Dispatch_type_(IRP_MJ_CLOSE)
DRIVER_DISPATCH CloseDispatch;

_Dispatch_type_(IRP_MJ_CREATE)
_Dispatch_type_(IRP_MJ_CREATE_NAMED_PIPE)
_Dispatch_type_(IRP_MJ_CLOSE)
_Dispatch_type_(IRP_MJ_READ)
_Dispatch_type_(IRP_MJ_WRITE)
_Dispatch_type_(IRP_MJ_QUERY_INFORMATION)
_Dispatch_type_(IRP_MJ_SET_INFORMATION)
_Dispatch_type_(IRP_MJ_QUERY_EA)
_Dispatch_type_(IRP_MJ_SET_EA)
_Dispatch_type_(IRP_MJ_FLUSH_BUFFERS)
_Dispatch_type_(IRP_MJ_QUERY_VOLUME_INFORMATION)
_Dispatch_type_(IRP_MJ_SET_VOLUME_INFORMATION)
_Dispatch_type_(IRP_MJ_DIRECTORY_CONTROL)
_Dispatch_type_(IRP_MJ_FILE_SYSTEM_CONTROL)
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
_Dispatch_type_(IRP_MJ_INTERNAL_DEVICE_CONTROL)
_Dispatch_type_(IRP_MJ_SHUTDOWN)
_Dispatch_type_(IRP_MJ_LOCK_CONTROL)
_Dispatch_type_(IRP_MJ_CLEANUP)
_Dispatch_type_(IRP_MJ_CREATE_MAILSLOT)
_Dispatch_type_(IRP_MJ_QUERY_SECURITY)
_Dispatch_type_(IRP_MJ_SET_SECURITY)
_Dispatch_type_(IRP_MJ_POWER)
_Dispatch_type_(IRP_MJ_SYSTEM_CONTROL)
_Dispatch_type_(IRP_MJ_DEVICE_CHANGE)
_Dispatch_type_(IRP_MJ_QUERY_QUOTA)
_Dispatch_type_(IRP_MJ_SET_QUOTA)
_Dispatch_type_(IRP_MJ_PNP)
DRIVER_DISPATCH UnsupportedDispatch;

DRIVER_INITIALIZE   DriverEntry;
DRIVER_UNLOAD       DriverUnload;

VOID DmLoadImageNotifyRoutine(
    _In_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo);

VOID DmProcessNotifyRoutine(
    _In_ HANDLE  ParentId,
    _In_ HANDLE  ProcessId,
    _In_ BOOLEAN  Create);


NTSTATUS DmpInit(
    VOID);

VOID DmpFreeGlobals(
    VOID);

VOID DmpImageLoadHandler(
    _In_ PUNICODE_STRING  FullImageName,
    _In_ PIMAGE_INFO  ImageInfo);

NTSTATUS DmWriteMemory(
    _In_ PVOID SrcAddress,
    _In_ PVOID DestAddress,
    _In_ ULONG Size,
    _In_ BOOLEAN Protect,
    _In_opt_ ULONG NewProtect,
    _Out_opt_ PULONG BytesWritten);

NTSTATUS DmpDisallowCallback(
    _In_ PIMAGE_INFO ImageInfo,
    _In_reads_bytes_opt_(HashLength) PUCHAR Hash,
    _In_opt_ ULONG HashLength,
    _In_ BOOLEAN UseWhiteList,
    _Out_opt_ PBOOLEAN SilentApprove);

NTSTATUS DmpBlockDriver(
    _In_ PVOID ImageBase);

NTSTATUS DmpLoadFilterCallback(
    _In_ PWSTR ImageNameBuffer,
    _In_ PIMAGE_INFO  ImageInfo,
    _In_reads_bytes_opt_(HashLength) PUCHAR Hash,
    _In_opt_ ULONG HashLength);

#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(INIT, DmpInit)

#pragma alloc_text(PAGE, DmLoadImageNotifyRoutine)
#pragma alloc_text(PAGE, DmProcessNotifyRoutine)
#pragma alloc_text(PAGE, DmpFreeGlobals)
#pragma alloc_text(PAGE, DmWriteMemory)

#pragma alloc_text(PAGE, DmpImageLoadHandler)
#pragma alloc_text(PAGE, DmpDisallowCallback)
#pragma alloc_text(PAGE, DmpBlockDriver)
#pragma alloc_text(PAGE, DmpLoadFilterCallback)

#pragma alloc_text(PAGE, DevioctlDispatch)
#pragma alloc_text(PAGE, CreateDispatch)
#pragma alloc_text(PAGE, CloseDispatch)
#pragma alloc_text(PAGE, UnsupportedDispatch)
#pragma alloc_text(PAGE, DriverUnload)
