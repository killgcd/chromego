@Echo Off
Title 从OSC云端更新 Agent 最新可用 IP
cd /d %~dp0
..\..\wget --ca-certificate=ca-bundle.crt -c https://coding.net/u/Alvin9999/p/pac/git/raw/master/proxy.user.ini
del "..\proxy.user.ini_backup"
ren "..\proxy.user.ini"  proxy.user.ini_backup
copy /y "%~dp0proxy.user.ini" ..\proxy.user.ini
del "%~dp0proxy.user.ini"
ECHO.&ECHO.已更新完成最新可用ipv6 ip,请按任意键退出,并重启程序. &PAUSE >NUL 2>NUL