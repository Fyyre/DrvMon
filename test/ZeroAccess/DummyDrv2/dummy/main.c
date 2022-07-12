/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017
*
*  TITLE:       MAIN.C
*
*  VERSION:     1.00
*
*  DATE:        10 Apr 2017
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include <ntddk.h>
#include "main.h"

#define DEBUGPRINT

/*
* DevioctlDispatch
*
* Purpose:
*
* IRP_MJ_DEVICE_CONTROL dispatch.
*
*/
NTSTATUS DevioctlDispatch(
	_In_ struct _DEVICE_OBJECT *DeviceObject,
	_Inout_ struct _IRP *Irp
	)
{
	NTSTATUS				status = STATUS_SUCCESS;
	ULONG					bytesIO = 0;
	PIO_STACK_LOCATION		stack;
	BOOLEAN					condition = FALSE;
	PINOUTPARAM             rp, wp;

	UNREFERENCED_PARAMETER(DeviceObject);

	DbgPrint("[DrvMonTest] %s IRP_MJ_DEVICE_CONTROL", __FUNCTION__);

	stack = IoGetCurrentIrpStackLocation(Irp);

	do {

		if (stack == NULL) {
			status = STATUS_INTERNAL_ERROR;
			break;
		}

		rp = (PINOUTPARAM)Irp->AssociatedIrp.SystemBuffer;
		wp = (PINOUTPARAM)Irp->AssociatedIrp.SystemBuffer;
		if (rp == NULL) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		switch (stack->Parameters.DeviceIoControl.IoControlCode) {
		case DUMMYDRV_REQUEST1:

			DbgPrint("[DrvMonTest] %s DUMMYDRV_REQUEST1 hit", __FUNCTION__);
			if (stack->Parameters.DeviceIoControl.InputBufferLength != sizeof(INOUT_PARAM)) {
				status = STATUS_INVALID_PARAMETER;
				break;
			}

			DbgPrint("[DrvMonTest] %s in params = %lx, %lx, %lx, %lx", __FUNCTION__, 
				rp->Param1, rp->Param2, rp->Param3, rp->Param4);

            wp->Param1 = 11111111;
			wp->Param2 = 22222222;
			wp->Param3 = 33333333;
			wp->Param4 = 44444444;

			status = STATUS_SUCCESS;
			bytesIO = sizeof(INOUT_PARAM);

			break;

		default:
			DbgPrint("[DrvMonTest] %s hit with invalid IoControlCode", __FUNCTION__);
			status = STATUS_INVALID_PARAMETER;
		};

	} while (condition);

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = bytesIO;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

/*
* UnsupportedDispatch
*
* Purpose:
*
* Unused IRP_MJ_* dispatch.
*
*/
NTSTATUS UnsupportedDispatch(
	_In_ struct _DEVICE_OBJECT *DeviceObject,
	_Inout_ struct _IRP *Irp
	)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_NOT_SUPPORTED;
}

/*
* CreateDispatch
*
* Purpose:
*
* IRP_MJ_CREATE dispatch.
*
*/
NTSTATUS CreateDispatch(
	_In_ struct _DEVICE_OBJECT *DeviceObject,
	_Inout_ struct _IRP *Irp
	)
{
	NTSTATUS status = Irp->IoStatus.Status;
	UNREFERENCED_PARAMETER(DeviceObject);

	DbgPrint("[DrvMonTest] %s Create", __FUNCTION__);

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

/*
* CloseDispatch
*
* Purpose:
*
* IRP_MJ_CLOSE dispatch.
*
*/
NTSTATUS CloseDispatch(
	_In_ struct _DEVICE_OBJECT *DeviceObject,
	_Inout_ struct _IRP *Irp
	)
{
	NTSTATUS status = Irp->IoStatus.Status;
	UNREFERENCED_PARAMETER(DeviceObject);

	DbgPrint("[DrvMonTest] %s Close", __FUNCTION__);

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

/*
* DriverUnload
*
* Purpose:
*
* Driver unload procedure.
*
*/
VOID DriverUnload(
    _In_  struct _DRIVER_OBJECT *DriverObject
)
{
    UNICODE_STRING str;
    PAGED_CODE();

    DbgPrint("[DrvMonTest] % Unload", __FUNCTION__);

    RtlInitUnicodeString(&str, L"\\DosDevices\\TestDrv");
    IoDeleteSymbolicLink(&str);
    IoDeleteDevice(DriverObject->DeviceObject);
}


/*
* DriverEntry
*
* Purpose:
*
* Driver base entry point.
*
*/
NTSTATUS DriverEntry(
  _In_  struct _DRIVER_OBJECT *DriverObject,
  _In_  PUNICODE_STRING RegistryPath
)
{
    NTSTATUS        status;
    UNICODE_STRING  SymLink, DevName;
    PDEVICE_OBJECT  devobj;
    ULONG           t;
 
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("[DrvMonTest] %s", __FUNCTION__);

    RtlInitUnicodeString(&DevName, L"\\Device\\TestDrv");
    status = IoCreateDevice(DriverObject, 0, &DevName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, TRUE, &devobj);

    DbgPrint("[DrvMonTest] %s IoCreateDevice(%wZ) = %lx", __FUNCTION__, DevName, status);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlInitUnicodeString(&SymLink, L"\\DosDevices\\TestDrv");
    status = IoCreateSymbolicLink(&SymLink, &DevName);

    DbgPrint("[DrvMonTest] %s IoCreateSymbolicLink(%wZ) = %lx", __FUNCTION__, SymLink, status);

    devobj->Flags |= DO_BUFFERED_IO;

    for (t = 0; t <= IRP_MJ_MAXIMUM_FUNCTION; t++)
        DriverObject->MajorFunction[t] = &UnsupportedDispatch;

    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = &DevioctlDispatch;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = &CreateDispatch;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = &CloseDispatch;
    DriverObject->DriverUnload = &DriverUnload;

    devobj->Flags &= ~DO_DEVICE_INITIALIZING;
	return status;
}
