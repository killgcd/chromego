@Echo Off
Title ��GitHub�ƶ˸��� Goflyway ��������
cd /d %~dp0
..\..\wget --ca-certificate=ca-bundle.crt -c https://gitlab.com/free9999/ipupdate/-/raw/master/goflyway/config.ini

if exist config.ini goto startcopy
echo ip����ʧ�ܣ�������ip_2����
pause
exit
:startcopy

del "..\config.ini_backup"
ren "..\config.ini"  config.ini_backup
copy /y "%~dp0config.ini" ..\config.ini
del "%~dp0config.ini"
ECHO.&ECHO.�Ѹ���������¿���Goflyway����,�밴������˳�,����������. &PAUSE >NUL 2>NUL
exit