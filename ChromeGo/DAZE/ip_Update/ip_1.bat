@Echo Off
setlocal enableDelayedExpansion
Title ��GitHub�ƶ˸��� DAZE ��������
cd /d %~dp0

set filename=config.ini
..\..\wget -t 1 --ca-certificate=ca-bundle.crt  https://gitlab.com/free9999/ipupdate/-/raw/master/DAZE/config.ini
rem ����ļ��Ƿ���ڣ�������������ʧ�ܣ����������سɹ�
if exist %filename% goto startcopy

set filename=config.ini
echo download ip1 failed,try download ip2 ...
..\..\wget -t 1 --ca-certificate=ca-bundle.crt https://coding.net/u/Alvin9999/p/pac/git/raw/master/DAZE/config.ini
if exist %filename% goto startcopy

rem 2�����ض�ʧ�ܣ�����ʾ�û��������˳�
echo ip����ʧ�ܣ�������Ƿ�����лл����������kebi2014@gmail.com
pause
exit

:startcopy
del "..\config.ini_backup"
ren "..\config.ini"  config.ini_backup
copy /y "%~dp0%filename%" ..\config.ini
del "%~dp0%filename%"
ECHO.&ECHO.�Ѹ���������¿���DAZE����,�밴������˳�,����������. &PAUSE >NUL 2>NUL
exit