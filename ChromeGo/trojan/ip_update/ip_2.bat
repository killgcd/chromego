@Echo Off
Title 从Coding.net云端更新 Trojan 最新配置
cd /d %~dp0
..\..\wget --ca-certificate=ca-bundle.crt -c https://coding.net/u/Alvin9999/p/ip/git/raw/master/config.json
del "..\config.json_backup"
ren "..\config.json"  config.json_backup
copy /y "%~dp0config.json" ..\config.json
del "%~dp0config.json"
ECHO.&ECHO.已更新IP配置信息～接下来更新证书文件～

..\..\wget --ca-certificate=ca-bundle.crt -c https://coding.net/u/Alvin9999/p/ip/git/raw/master/private.crt
del "..\private.crt_backup"
ren "..\private.crt"  private.crt_backup
copy /y "%~dp0private.crt" ..\private.crt
del "%~dp0private.crt"
ECHO.&ECHO.已更新证书文件～

ECHO.&ECHO.已更新完成最新可用trojan配置,请按任意键退出,并重启程序. &PAUSE >NUL 2>NUL