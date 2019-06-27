@echo off
CD /D "%~dp0"
start "" "%~dp0Brook\BrookTools.exe"
echo µÈ´ý·­Ç½Èí¼þÆô¶¯£¬ÇëÉÔºò...
start /wait "" "%~dp0waiting.vbs"
IF EXIST %~dp0Browser\chrome.exe (
    start %~dp0Browser\chrome.exe --user-data-dir=%~dp0chrome-user-data --proxy-server="socks5://127.0.0.1:2080" --host-resolver-rules="MAP * ~NOTFOUND , EXCLUDE 127.0.0.1" https://www.bannedbook.org/bnews/fq/?utm_source=chgo-brook
) ELSE (
    start chrome.exe --user-data-dir=%~dp0chrome-user-data  --proxy-server="socks5://127.0.0.1:2080" --host-resolver-rules="MAP * ~NOTFOUND , EXCLUDE 127.0.0.1"  https://www.bannedbook.org/bnews/fq/?utm_source=chgo-brook
)