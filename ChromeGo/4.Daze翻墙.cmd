%%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a 
cls
@echo off

echo �Ƿ�ִ��IP���£�IP���´��ƶ˸���IP�����Խ���������⣡
choice /C 12 /T 15 /D 2 /M "1.ip����,2.����"
if errorlevel 2 goto startfq
if errorlevel 1 goto ip1

:ip1
start /wait "" "%~dp0DAZE\ip_Update\ip_1.bat"
goto startfq

:startfq
start %~dp0DAZE\DAZETools.exe
echo �ȴ���ǽ������������Ժ�...
start /wait "" "%~dp0waiting.vbs"
IF EXIST %~dp0Browser\chrome.exe (
    start %~dp0Browser\chrome.exe --user-data-dir=%~dp0chrome-user-data --proxy-server=127.0.0.1:3080 https://www.bannedbook.org/bnews/fq/?utm_source=DAZE
) ELSE (
	%SystemRoot%\System32\reg.exe query "HKLM\Software\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe" >nul 2>&1
	IF  not errorlevel 1 (
    start chrome.exe --user-data-dir=%~dp0chrome-user-data --proxy-server=127.0.0.1:3080 https://www.bannedbook.org/bnews/fq/?utm_source=DAZE
	) else ( 
		echo Chrome����������ڻ�û����ȷ��װ���볢�����°�װChrome�����
		echo ���߲������°취��
		echo �Ҽ��������Google Chromeͼ�꣬�ٵ����ԣ��ҵ�chrome.exe�ļ���·����Ȼ����Ǹ�Ŀ¼����chrome.exe ��ͬ�Ǹ�Ŀ¼�µ��������ļ��к��ļ���һ�𿽱���ChromeGo�ļ����µ�BrowserĿ¼���棬Ȼ����������ChromeGo�ķ�ǽ�ű���
		pause
	)
)