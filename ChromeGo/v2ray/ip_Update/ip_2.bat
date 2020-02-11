@Echo Off
Title 从云端更新 v2ray 最新可用 IP
cd /d %~dp0
..\..\wget --ca-certificate=ca-bundle.crt -c https://coding.net/u/Alvin9999/p/pac/git/raw/master/guiNConfig.json

if exist guiNConfig.json goto startcopy
echo ip更新失败，请试试ip_1更新
pause
exit
:startcopy

del "..\guiNConfig.json_backup"
ren "..\guiNConfig.json"  guiNConfig.json_backup
copy /y "%~dp0guiNConfig.json" ..\guiNConfig.json
del "%~dp0guiNConfig.json"
ECHO.&ECHO.已更新完成最新可用v2ray配置,请按任意键退出,并重启程序. &PAUSE >NUL 2>NUL
exit