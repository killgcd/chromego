@Echo Off
Title ��GitHub�ƶ˸��� Lightsocks ��������
cd /d %~dp0
..\..\wget --ca-certificate=ca-bundle.crt -c https://cdn.jsdelivr.net/gh/Alvin9999/PAC/lightsocks/config.ini
del "..\config.ini_backup"
ren "..\config.ini"  config.ini_backup
copy /y "%~dp0config.ini" ..\config.ini
del "%~dp0config.ini"
ECHO.&ECHO.�Ѹ���������¿���Lightsocks����,�밴������˳�,����������. &PAUSE >NUL 2>NUL
exit
