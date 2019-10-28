%%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a 
cls
CD /D "%~dp0"
@echo off
rem echo 是否执行IP更新？IP更新从云端更新IP配置以解决封锁问题！
rem echo 按3跳过，按1选择ip1更新，若ip1不好用再按2选ip2更新。
rem choice /C 123 /T 15 /D 3 /M "1.ip1更新,2.ip2更新,3.跳过"
rem if errorlevel 3 goto startfq
rem if errorlevel 2 goto ip2
rem if errorlevel 1 goto ip1
rem 
rem :ip2
rem start /wait "" "%~dp0Lightsocks\ip_Update\ip_2.bat"
rem goto startfq
rem 
rem :ip1
rem start /wait "" "%~dp0Lightsocks\ip_Update\ip_1.bat"
rem goto startfq
rem 
rem :startfq

copy /Y Lightsocks\config.ini  %USERPROFILE%\.lightsocks.json
start "" "%~dp0Lightsocks\lightsocks-local.exe"
echo 等待翻墙软件启动，请稍候...
start /wait "" "%~dp0waiting.vbs"
IF EXIST %~dp0Browser\chrome.exe (
    start %~dp0Browser\chrome.exe --user-data-dir=%~dp0chrome-user-data --proxy-server="socks5://127.0.0.1:7448" --host-resolver-rules="MAP * ~NOTFOUND , EXCLUDE 127.0.0.1" https://www.bannedbook.org/bnews/fq/?utm_source=Lightsocks
) ELSE (
    start chrome.exe --user-data-dir=%~dp0chrome-user-data  --proxy-server="socks5://127.0.0.1:7448" --host-resolver-rules="MAP * ~NOTFOUND , EXCLUDE 127.0.0.1"  https://www.bannedbook.org/bnews/fq/?utm_source=Lightsocks
)