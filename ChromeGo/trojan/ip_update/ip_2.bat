@Echo Off
Title ��Coding.net�ƶ˸��� Trojan ��������
cd /d %~dp0
..\..\wget --ca-certificate=ca-bundle.crt -c https://cdn.jsdelivr.net/gh/Alvin9999/pac2@latest/config.json
..\..\wget --ca-certificate=ca-bundle.crt -c https://cdn.jsdelivr.net/gh/Alvin9999/pac2@latest/crt/private.crt

if exist config.json goto startcopy
echo ip����ʧ�ܣ�������ip_1����
pause
exit
:startcopy

del "..\config.json_backup"
ren "..\config.json"  config.json_backup
copy /y "%~dp0config.json" ..\config.json
del "%~dp0config.json"
ECHO.&ECHO.�Ѹ���IP������Ϣ������������֤���ļ���

del "..\private.crt_backup"
ren "..\private.crt"  private.crt_backup
copy /y "%~dp0private.crt" ..\private.crt
del "%~dp0private.crt"
ECHO.&ECHO.�Ѹ���֤���ļ���

ECHO.&ECHO.�Ѹ���������¿���trojan����,�밴������˳�,����������. &PAUSE >NUL 2>NUL
exit