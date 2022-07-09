/*******************************************************************************
*
*  (C) COPYRIGHT Fyyre & EP_X0FF, 2010 - 2017
*
*  TITLE:       LOGGER.H
*
*  VERSION:     3.00
*
*  DATE:        01 Apr 2017
*
*  Header file for DrvMon logger routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

#define LOG_PIPE_BUFFER_SIZE 0x1000

#define LoggerErrorEstablishLink  L"Failed to create communication endpoint."
#define LoggerErrorInstanceThread L"Error creating instance thread."

BOOL LoggerInit(
    VOID);
