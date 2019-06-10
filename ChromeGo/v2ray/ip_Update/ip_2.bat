@Echo Off
Title ´ÓCODÔÆ¶Ë¸üGÂ v2ray ×îGÂ¿ÉÓÃ IP or ÅäÖÃ
cd /d %~dp0
..\..\wget --ca-certificate=ca-bundle.crt -c https://coding.net/u/Alvin9999/p/pac/git/raw/master/guiNConfig.json
del "..\guiNConfig.json_backup"
ren "..\guiNConfig.json"  guiNConfig.json_backup
copy /y "%~dp0guiNConfig.json" ..\guiNConfig.json
del "%~dp0guiNConfig.json"
ECHO.&ECHO.ÒÑ¸üGÂÍê³É×îGÂ¿ÉÓÃv2rayÅäÖÃ,Çë°´ÈÎÒâ¼üÍË³ö,²¢ÖØÆô³ÌGò. &PAUSE >NUL 2>NUL