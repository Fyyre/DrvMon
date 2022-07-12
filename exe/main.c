/*******************************************************************************
*
*  (C) COPYRIGHT Fyyre & EP_X0FF, 2010 - 2018
*
*  TITLE:       MAIN.C
*
*  VERSION:     3.01
*
*  DATE:        10 Nov 2018
*
*  Program entry point.
*
*  Code name: Sendai
*
*  May 2011: created  2.0
*  Jan 2012: revision 2.1
*  Feb 2012: revision 2.1.1
*  Feb 2013: revision 2.2
*  Dec 2014: revision 2.2.1
*  Apr 2017: created  3.0
*  Nov 2018: revision 3.0.1
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

#pragma data_seg("shrd")
volatile LONG g_lApplicationInstances = 0;
#pragma data_seg()
#pragma comment(linker, "/Section:shrd,RWS")

WCHAR g_szOutputDirectory[MAX_PATH * 2];
WCHAR g_szTempDrvName[MAX_EVENT_DRIVER_NAME_LENGTH];


DRVMONCONTEXT g_ctx;
UNICODE_STRING g_OutputDirectory;

/*
* DmInit
*
* Purpose:
*
* Driver Monitor initialization routine.
*
*/
ULONG DmInit(
    VOID
)
{
    BOOL bCond = FALSE, bNoErrors = FALSE;
    ULONG dwResult = ERROR_SUCCESS;

    NTSTATUS Status;
    UNICODE_STRING SectionName;
    UNICODE_STRING EventName;
    OBJECT_ATTRIBUTES Obja;
    LARGE_INTEGER MaximumSize;
    SIZE_T ViewSize = SHARED_SPACE_SIZE;

    do {
        RtlSecureZeroMemory(&g_ctx, sizeof(DRVMONCONTEXT));

        //
        // Query version first.
        //
        g_ctx.osver.dwOSVersionInfoSize = sizeof(OSVERSIONINFOW);
        if (NT_SUCCESS(RtlGetVersion(&g_ctx.osver))) {
            if (g_ctx.osver.dwMajorVersion < 6) {
                dwResult = ERROR_INSTALL_PLATFORM_UNSUPPORTED;
                break;
            }
        }

        //
        // Create private help.
        //
        g_ctx.dmHeap = RtlCreateHeap(HEAP_GROWABLE, NULL, 0, 0, NULL, NULL);
        if (g_ctx.dmHeap == NULL) {
            dwResult = ERROR_NOT_ENOUGH_MEMORY;
            break;
        }

        RtlSetHeapInformation(g_ctx.dmHeap, HeapEnableTerminationOnCorruption, NULL, 0);

        //
        // Remember hInstance and current directory.
        //
        g_ctx.hInstance = GetModuleHandle(NULL);

        EventName.Buffer = NULL;
        EventName.Length = 0;
        EventName.MaximumLength = 0;

        //
        // Create data buffer ready event.
        //
        g_ctx.DataBufferReadyEvent = NULL;
        RtlInitUnicodeString(&EventName, DM_DATAREADYEVENT);
        InitializeObjectAttributes(&Obja, &EventName, OBJ_CASE_INSENSITIVE, NULL, NULL);
        Status = NtCreateEvent(&g_ctx.DataBufferReadyEvent, EVENT_ALL_ACCESS, &Obja, SynchronizationEvent, FALSE);
        if (!NT_SUCCESS(Status)) {
            dwResult = RtlNtStatusToDosError(Status);
            break;
        }

        //
        // Create data buffer complete event.
        //
        g_ctx.DataBufferCompleteEvent = NULL;
        RtlInitUnicodeString(&EventName, DM_DATACMPLTEVENT);
        InitializeObjectAttributes(&Obja, &EventName, OBJ_CASE_INSENSITIVE, NULL, NULL);
        Status = NtCreateEvent(&g_ctx.DataBufferCompleteEvent, EVENT_ALL_ACCESS, &Obja, SynchronizationEvent, FALSE);
        if (!NT_SUCCESS(Status)) {
            dwResult = RtlNtStatusToDosError(Status);
            break;
        }

        SectionName.Buffer = NULL;
        SectionName.Length = 0;
        SectionName.MaximumLength = 0;

        //
        // Create shared section.
        //
        RtlInitUnicodeString(&SectionName, DM_SHAREDSECTION);
        InitializeObjectAttributes(&Obja, &SectionName, OBJ_CASE_INSENSITIVE, NULL, NULL);
        g_ctx.hMemorySection = NULL;
        MaximumSize.QuadPart = SHARED_SPACE_SIZE;
        Status = NtCreateSection(
            &g_ctx.hMemorySection,
            SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_QUERY,
            &Obja,
            &MaximumSize,
            PAGE_READWRITE,
            SEC_COMMIT,
            NULL);

        //
        // If the section already exist, open it.
        //
        if (Status == STATUS_OBJECT_NAME_COLLISION) {
            Status = NtOpenSection(
                &g_ctx.hMemorySection,
                SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_QUERY,
                &Obja);
        }

        if (!NT_SUCCESS(Status)) {
            dwResult = RtlNtStatusToDosError(Status);
            break;
        }

        //
        // Map view of section.
        //
        g_ctx.SharedMemory = NULL;
        Status = NtMapViewOfSection(
            g_ctx.hMemorySection,
            NtCurrentProcess(),
            &g_ctx.SharedMemory,
            0,
            SHARED_SPACE_SIZE,
            NULL,
            &ViewSize,
            ViewUnmap,
            MEM_TOP_DOWN,
            PAGE_READWRITE);

        if (NT_SUCCESS(Status)) {
            if (g_ctx.SharedMemory != NULL) {
                RtlSecureZeroMemory(g_ctx.SharedMemory, SHARED_SPACE_SIZE);
            }
            bNoErrors = TRUE;
        }
        else {
            dwResult = RtlNtStatusToDosError(Status);
            break;
        }

        //
        // Register wait routine.
        //
        g_ctx.hNotifyWait = NULL;
        if (!RegisterWaitForSingleObject(&g_ctx.hNotifyWait, g_ctx.DataBufferReadyEvent,
            &DmUINotify, NULL, INFINITE, WT_EXECUTELONGFUNCTION))
        {
            dwResult = GetLastError();
            break;
        }

    } while (bCond);

    //
    // Some error take place, cleanup.
    //
    if (bNoErrors == FALSE) {
        if (g_ctx.SharedMemory != NULL) {
            NtUnmapViewOfSection(NtCurrentProcess(), g_ctx.SharedMemory);
            g_ctx.SharedMemory = NULL;
        }
        if (g_ctx.hMemorySection != NULL) {
            NtClose(g_ctx.hMemorySection);
            g_ctx.hMemorySection = NULL;
        }
        if (g_ctx.DataBufferReadyEvent != NULL) {
            NtClose(g_ctx.DataBufferReadyEvent);
            g_ctx.DataBufferReadyEvent = NULL;
        }
        if (g_ctx.DataBufferCompleteEvent != NULL) {
            NtClose(g_ctx.DataBufferCompleteEvent);
            g_ctx.DataBufferCompleteEvent = NULL;
        }
    }
    return dwResult;
}

/*
* DmMain
*
* Purpose:
*
* Driver Monitor main.
*
*/
VOID DmMain(
    VOID
)
{
    ULONG dwResult;

    dwResult = DmInit();

    if (dwResult != ERROR_SUCCESS) {
        switch (dwResult) {
        case ERROR_INTERNAL_ERROR:
            MessageBox(GetDesktopWindow(), TEXT("Unexpected internal error."), NULL, MB_ICONERROR);
            break;
        case ERROR_NOT_ENOUGH_MEMORY:
            MessageBox(GetDesktopWindow(), TEXT("Not enough memory to complete operation."), NULL, MB_ICONERROR);
            break;
        case ERROR_INSTALL_PLATFORM_UNSUPPORTED:
            MessageBox(GetDesktopWindow(), TEXT("This Windows version is not supported."), NULL, MB_ICONERROR);
            break;
        default:
            break;
        }
        ExitProcess(dwResult);
        return;
    }

    //
    // Initialize whitelist.
    //
    KnownDriversCreate();

    DmUIMain();

    //
    // Destroy whitelist
    //
    KnownDriversDestroy();
}

/*
* main
*
* Purpose:
*
* Program entrypoint.
*
*/
void main()
{
    LONG x;

    __security_init_cookie();

    //
    // Do not allow multiple application instances.
    //
    x = InterlockedIncrement((PLONG)&g_lApplicationInstances);
    if (x > 1) {
        MessageBox(NULL, DM_MULTIPLE_INSTANCES, NULL, MB_ICONINFORMATION);
        InterlockedDecrement((PLONG)&g_lApplicationInstances);
        ExitProcess(0);
    }

    DmMain();

    //decrement instances count
    InterlockedDecrement((PLONG)&g_lApplicationInstances);
    ExitProcess(0);
}
