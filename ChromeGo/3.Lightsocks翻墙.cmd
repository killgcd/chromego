%%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a 
cls
CD /D "%~dp0"
@echo off
rem echo �Ƿ�ִ��IP���£�IP���´��ƶ˸���IP�����Խ���������⣡
rem echo ��3��������1ѡ��ip1���£���ip1�������ٰ�2ѡip2���¡�
rem choice /C 123 /T 15 /D 3 /M "1.ip1����,2.ip2����,3.����"
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
echo �ȴ���ǽ������������Ժ�...
start /wait "" "%~dp0waiting.vbs"
IF EXIST %~dp0Browser\chrome.exe (
    start %~dp0Browser\chrome.exe --user-data-dir=%~dp0chrome-user-data --proxy-server="socks5://127.0.0.1:7448" --host-resolver-rules="MAP * ~NOTFOUND , EXCLUDE 127.0.0.1" https://www.bannedbook.org/bnews/fq/?utm_source=Lightsocks
) ELSE (
	%SystemRoot%\System32\reg.exe query "HKLM\Software\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe" >nul 2>&1
	IF  not errorlevel 1 (
    start chrome.exe --user-data-dir=%~dp0chrome-user-data  --proxy-server="socks5://127.0.0.1:7448" --host-resolver-rules="MAP * ~NOTFOUND , EXCLUDE 127.0.0.1"  https://www.bannedbook.org/bnews/fq/?utm_source=Lightsocks
	) else ( 
		echo Chrome����������ڻ�û����ȷ��װ���볢�����°�װChrome�����
		echo ���߲������°취��
		echo �Ҽ��������Google Chromeͼ�꣬�ٵ����ԣ��ҵ�chrome.exe�ļ���·����Ȼ����Ǹ�Ŀ¼����chrome.exe ��ͬ�Ǹ�Ŀ¼�µ��������ļ��к��ļ���һ�𿽱���ChromeGo�ļ����µ�BrowserĿ¼���棬Ȼ����������ChromeGo�ķ�ǽ�ű���
		pause
	)
)