%%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a %%a 
cls
@echo off

echo �Ƿ�ִ��IP���£�IP���´��ƶ˸���IP�����Խ���������⣡
echo ��3��������1ѡ��ip1���£���ip1�������ٰ�2ѡip2���¡�
choice /C 123 /T 15 /D 3 /M "1.ip1����,2.ip2����,3.����"
if errorlevel 3 goto startfq
if errorlevel 2 goto ip2
if errorlevel 1 goto ip1

:ip2
start /wait "" "%~dp0Goflyway\ip_Update\ip_2.bat"
goto startfq

:ip1
start /wait "" "%~dp0Goflyway\ip_Update\ip_1.bat"
goto startfq

:startfq
start %~dp0Goflyway\GoflywayTools.exe
echo �ȴ���ǽ������������Ժ�...
start /wait "" "%~dp0waiting.vbs"
IF EXIST %~dp0Browser\chrome.exe (
    start %~dp0Browser\chrome.exe --user-data-dir=%~dp0chrome-user-data --proxy-server=127.0.0.1:8100 https://www.bannedbook.org/bnews/fq/?utm_source=Goflyway
) ELSE (
	%SystemRoot%\System32\reg.exe query "HKLM\Software\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe" >nul 2>&1
	IF  not errorlevel 1 (
    start chrome.exe --user-data-dir=%~dp0chrome-user-data --proxy-server=127.0.0.1:8100 https://www.bannedbook.org/bnews/fq/?utm_source=Goflyway
	) else ( 
		echo Chrome����������ڻ�û����ȷ��װ���볢�����°�װChrome�����
		echo ���߲������°취��
		echo �Ҽ��������Google Chromeͼ�꣬�ٵ����ԣ��ҵ�chrome.exe�ļ���·����Ȼ����Ǹ�Ŀ¼����chrome.exe ��ͬ�Ǹ�Ŀ¼�µ��������ļ��к��ļ���һ�𿽱���ChromeGo�ļ����µ�BrowserĿ¼���棬Ȼ����������ChromeGo�ķ�ǽ�ű���
		pause
	)
)