@Echo Off
Title ���ƶ˸��� v2ray ���¿��� IP
cd /d %~dp0
..\..\wget --ca-certificate=ca-bundle.crt -c https://coding.net/u/Alvin9999/p/pac/git/raw/master/guiNConfig.json

if exist guiNConfig.json goto startcopy
echo ip����ʧ�ܣ�������ip_1����
pause
exit
:startcopy

del "..\guiNConfig.json_backup"
ren "..\guiNConfig.json"  guiNConfig.json_backup
copy /y "%~dp0guiNConfig.json" ..\guiNConfig.json
del "%~dp0guiNConfig.json"
ECHO update ok. 
PAUSE
exit