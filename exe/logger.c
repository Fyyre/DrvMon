/*******************************************************************************
*
*  (C) COPYRIGHT Fyyre & EP_X0FF, 2010 - 2018
*
*  TITLE:       LOGGER.C
*
*  VERSION:     3.01
*
*  DATE:        10 Nov 2018
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

#define LoggerShowError(Text) MessageBox(GetForegroundWindow(), Text, NULL, MB_ICONERROR);

/*
* LoggerPipeInstanceThread
*
* Purpose:
*
* Named pipe instance handler, processes events from driver.
*
*/
DWORD WINAPI LoggerPipeInstanceThread(
    LPVOID lpParam
)
{
    HANDLE hPipe = (HANDLE)lpParam;
    DWORD dwRead, dwLen = 0;
    PUCHAR Data = NULL;
    PUCHAR DataPtr = NULL;
    DWORD dwTotalReaded = 0, dwReadLen = 0;
    PDRVMON_EVENT pEvent = NULL;

    while (ReadFile(hPipe, (PVOID)&dwLen, sizeof(dwLen), &dwRead, NULL)) {

        if (dwLen > 0) {
            Data = (PUCHAR)supHeapAlloc((SIZE_T)dwLen);
            if (Data) {
                DataPtr = Data;
                dwReadLen = dwLen;
            read_again:
                if (ReadFile(hPipe, DataPtr, dwReadLen, &dwRead, NULL)) {
                    dwTotalReaded += dwRead;
                    if (dwLen > dwTotalReaded) {
                        DataPtr += dwRead;
                        dwReadLen -= dwRead;
                        goto read_again;
                    }
                    pEvent = (PDRVMON_EVENT)Data;
                    DmUIAddEvent(pEvent);
                }
                supHeapFree(Data);
            }
            else {
                LoggerShowError(DM_OUT_OF_MEMORY);
            }
        }
        dwLen = 0;
    }
    return 0;
}

/*
* LoggerServerThread
*
* Purpose:
*
* Server waiting for a client to connect to an instance of a named pipe.
*
*/
DWORD WINAPI LoggerServerThread(
    _In_ LPVOID lpParam
)
{
    HANDLE hPipe;
    HANDLE hThread;
    BOOL bConnected;

    UNREFERENCED_PARAMETER(lpParam);

    while (TRUE) {

        hPipe = CreateNamedPipe(
            LOG_PIPE_NAME,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            LOG_PIPE_BUFFER_SIZE,
            LOG_PIPE_BUFFER_SIZE,
            INFINITE,
            NULL);

        if (hPipe == INVALID_HANDLE_VALUE) {
            LoggerShowError(LoggerErrorEstablishLink);
            return 0;
        }
        bConnected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (bConnected) {

            hThread = CreateThread(NULL, 0, LoggerPipeInstanceThread, (LPVOID)hPipe, 0, NULL);
            if (hThread == NULL) {
                LoggerShowError(LoggerErrorInstanceThread);
                return 0;
            }
            else {
                CloseHandle(hThread);
            }
        }
        else {
            CloseHandle(hPipe);
        }

    }
}

/*
* LoggerInit
*
* Purpose:
*
* Create logger server thread.
*
*/
BOOL LoggerInit(
    VOID
)
{
    HANDLE hServerThread = NULL;

    hServerThread = CreateThread(NULL, 0, LoggerServerThread, NULL, 0, NULL);
    if (hServerThread) {
        CloseHandle(hServerThread);
        Sleep(500);
        return TRUE;
    }
    return FALSE;
}
