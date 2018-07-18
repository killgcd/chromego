@Echo Off
Title 从COD云端更新 GoProxy 最新可用 IP or 配置
cd /d %~dp0
..\..\wget --ca-certificate=ca-bundle.crt -c https://coding.net/u/Alvin9999/p/pac/git/raw/master/ipv6/gae.user.json
del "..\gae.user.json_backup"
ren "..\gae.user.json"  gae.user.json_backup
copy /y "%~dp0gae.user.json" ..\gae.user.json
del "%~dp0gae.user.json"
ECHO.&ECHO.已更新完成最新可用IPv6 ip,请按任意键退出,并重启程序. &PAUSE >NUL 2>NUL