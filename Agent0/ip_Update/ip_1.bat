@Echo Off
Title 从GitHub云端更新 Agent 最新可用 IP
cd /d %~dp0
..\..\wget --ca-certificate=ca-bundle.crt -c https://raw.githubusercontent.com/Alvin9999/PAC/master/gae.user.json
del "..\gae.user.json_backup"
ren "..\gae.user.json"  gae.user.json_backup
copy /y "%~dp0gae.user.json" ..\gae.user.json
del "%~dp0gae.user.json"
ECHO.&ECHO.已更新完成最新可用Quic IP,请按任意键退出,并重启程序. &PAUSE >NUL 2>NUL