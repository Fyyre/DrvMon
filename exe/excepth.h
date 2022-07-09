/*******************************************************************************
*
*  (C) COPYRIGHT Fyyre & EP_X0FF, 2010 - 2017
*
*  TITLE:       EXCEPTH.H
*
*  VERSION:     3.00
*
*  DATE:        10 Apr 2017
*
*  Common header file for the exception handling routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

INT exceptFilter(
    _In_ UINT ExceptionCode,
    _In_ EXCEPTION_POINTERS *ExceptionPointers
);
