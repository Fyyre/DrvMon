set certsdir=C:\Certs\
set signtooldir=C:\Program Files (x86)\Windows Kits\10\bin\x64\
set outputdir=C:\MAKEEXE\DrvMon\exe\output\x64\ReleaseSigned\
set signdir=C:\MAKEEXE\DrvMon\signing\

"%signdir%stripdebug.exe" %1

"%signtooldir%signtool.exe" sign /sha1 C17761DD3B2FCCB2AF39A7A6D888AE6E646637F1 /ac "%certsdir%thawte.cer" /ph /fd SHA256 /v /tr http://sha256timestamp.ws.symantec.com/sha256/timestamp %1
