/*******************************************************************************
*
*  (C) COPYRIGHT Fyyre & EP_X0FF, 2010 - 2018
*
*  TITLE:       CONSTS.H
*
*  VERSION:     3.01
*
*  DATE:        10 Nov 2018
*
*  Global consts definition file.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

#define MAINWINDOWCLASSNAME     L"DrvMon64Class"
#define FULLPROGRAMNAME         L"Driver Monitor"
#define PROGRAMNAME             L"DrvMon"

#define DM_SETTINGS_KEY         L"Software\\DM"
#define DM_SETTINGS_VALUE       L"Settings"
#define DM_SETTING_OUTDIR       L"OutputDirectory"
#define DM_WHITELIST_KEY        L"KdList"
#define DM_WHITELIST_VALUE      L"KdEntry"

#define DM_PROPERTIES_VERB      L"properties"
#define DM_EXPLORE_VERB         L"explore"
#define DM_OPEN_VERB            L"open"

#define DM_HELPFILE             L"\\drvmon.chm"

#define LOG_PIPE_NAME           L"\\\\.\\pipe\\DrvMonPipe"

#define WL_SECTION_NAME         L"Whitelist"
#define WL_VALUE_NAME           L"Value"

#define SYS_EXTENSION           L".sys"

#define VGA_DLL                 L"\\System32\\vga.dll"

#define HHCTRLOCXKEY            L"CLSID\\{ADB880A6-D8FF-11CF-9377-00AA003B7A11}\\InprocServer32"
#define HHCTRLOCX               L"hhctrl.ocx"

#define DM_DEFAULT_LOG_FILE     L"DmLog.txt"
#define DM_LOG_EXT              L"*.txt"

#define DM_SAVEDLG_TXT_FILTER   L"Text files\0*.txt\0\0"
#define DM_OPENDLG_ALL_FILTER   L"All files\0*.*\0\0"

#define DM_DRIVER_NAME          L"Sendai.sys"
#define DM_DISPLAY_NAME         L"Sendai"
#define DM_DEVICE_NAME          L"\\Device\\Sendai"
#define DM_DATAREADYEVENT       L"\\BaseNamedObjects\\SendaiDataReadyEvent"
#define DM_DATACMPLTEVENT       L"\\BaseNamedObjects\\SendaiDataCompleteEvent"
#define DM_SHAREDSECTION        L"\\BaseNamedObjects\\SendaiSharedSection"

// about box messages
#define DM_VERSION              L"3.0.1.1811"
#define DM_COPYRIGHT            L"© 2010 - 2018 DrvMon, EP_X0FF && Fyyre"
#define DM_BUILD_STRING         L"Build date: "

#define DM_FORMATTED_TIME_VALUE L"%02hd:%02hd:%02hd.%04hd"

#define DM_ERROR_SETTINGS_SAVE  L"Could not save settings"

#define DM_EVENT_SELECT_OUTDIR  L"Select output directory"
#define DM_EVENT_NEW_OUTDIR     L"New output directory "

#define DM_EVENT_AUTOSCROLL_ON  L"Auto scroll enabled"
#define DM_EVENT_AUTOSCROLL_OFF L"Auto scroll disabled"

#define DM_EVENT_CAPTURE_ON     L"Driver capturing enabled"
#define DM_EVENT_CAPTURE_OFF    L"Driver capturing disabled"

#define DM_EVENT_BLOCK_ON       L"Drivers loading autoblock enabled"
#define DM_EVENT_BLOCK_OFF      L"Drivers loading autoblock disabled"


#define DM_MULTIPLE_INSTANCES   L"Another instance already running, close it before."
#define DM_OUT_OF_MEMORY        L"Insufficient memory."


#define DM_GOOLGE_SEARCH        L"https://www.google.com/search?q="
#define DM_GOOGLE_SEARCH_LENGTH sizeof(DM_GOOLGE_SEARCH) - sizeof(WCHAR)

// whitelist messages
#define DM_WHITELIST_ADD_OK     L"Successfully added to whitelist."
#define DM_WHITELIST_ADD_ERROR  L"Error adding to whitelist."
#define DM_WHITELIST_DUPLICATE  L"This item is already in list."
#define DM_ERROR_CALC_HASH      L"Error while calculating hash for the file."
#define DM_ERROR_OUT_OF_MEM     L"Error, not enough memory."
#define DM_ERROR_SEND_REQUEST   L"Error while sending request to the driver."
#define DM_CONFIRM_DELETE       L"Are you sure want to delete this entry?"

// columns
#define LV_EVENT    L"Event"
#define LV_DESC     L"Description"
#define LV_TIME     L"Time"
#define LV_FILENAME L"File Name"
#define LV_HASH     L"Hash"

// event system messages
#define EVENT_STR_ERROR              L"Error"
#define EVENT_STR_LOADIMAGE          L"ImageLoad"
#define EVENT_STR_COLLECTED          L"Captured"
#define EVENT_STR_DENIED             L"Denied"
#define EVENT_STR_ALLOWED            L"Allowed"
#define EVENT_INFO                   L"DrvMon"
#define EVENT_STR_DRV_ERROR          L"Driver error"
#define EVENT_STR_APP_ERROR          L"Application error"

#define DM_BLOCK_DRIVERS_WARNING_TYPE_2   L"Are you sure?\
 This will disable all drivers loading on current machine.\n\
This may cause system instability and may result in data loss.\n\
Make sure you have added important system modules to whitelist (if required)."

#define DM_BLOCK_DRIVERS_WARNING_TYPE_1   (DM_BLOCK_DRIVERS_WARNING_TYPE_2\
 L"\n\nNote: You have enabled manual driver loading confirmation.\n\
If you continue then it will be turned off automaticaly.")
