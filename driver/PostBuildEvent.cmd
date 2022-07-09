rem This script is for "Release" configuration.
rem It copy compiled unsigned driver to application driver resource dir.

set outputdir="C:\MAKEEXE\DrvMon\driver\output\x64\Release\"
set drvresdir="C:\MAKEEXE\DrvMon\exe\drv\"

copy /y %outputdir%DrvMon.sys %drvresdir%DrvMon.sys
