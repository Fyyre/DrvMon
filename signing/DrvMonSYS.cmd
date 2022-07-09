echo Sign DrvMon

set certsdir=C:\Certs\
set signtooldir=C:\Program Files (x86)\Windows Kits\10\bin\x64\
set outputdir=C:\MAKEEXE\DrvMon\driver\output\x64\ReleaseSigned\
set drvresdir=C:\MAKEEXE\DrvMon\exe\drv\

"%signtooldir%signtool.exe" sign /sha1 C17761DD3B2FCCB2AF39A7A6D888AE6E646637F1 /ac "%certsdir%thawte.cer" /ph /fd SHA256 /v /tr http://sha256timestamp.ws.symantec.com/sha256/timestamp %1

echo Copy DrvMon.sys to Application resources directory

copy /y "%outputdir%DrvMon.sys" "%drvresdir%DrvMonSigned.sys"
pause