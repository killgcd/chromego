@echo off
:Init
Title CMD
MODE con: Cols=40 Lines=23

:BatchGotAdmin
:--------------------------------------
>nul 2>&1 "%SYSTEMROOT%\System32\cacls.exe" "%SYSTEMROOT%\System32\config\system"
if '%ERRORLEVEL%' neq '0' (
    Goto UACPrompt
) else ( Goto GotAdmin )
:UACPrompt
    echo 获取管理员权限。。。
    echo Set UAC = CreateObject^("Shell.Application"^) > "%TEMP%\getAdmin.vbs"
    Set "params=%* "
    Set "params=%params:"=""%"
    echo UAC.ShellExecute "cmd.exe", "/c """"%~f0"" %params%""", "", "runas", 1 >> "%TEMP%\getAdmin.vbs"
    "%TEMP%\getAdmin.vbs"
    del /q /f "%TEMP%\getAdmin.vbs"
    Exit /b
:GotAdmin
    Pushd "%CD%"
    cd /d "%~dp0"
:--------------------------------------

:: 判断输入参数
if /i `%1` == `enableIPv6` Goto EnableIPv6
if /i `%1` == `disableIPv6` Goto DisableIPv6

:Start
Color 2f
MODE con: Cols=40 Lines=23
Set tle=IPv6 配置
Set var=0

:Menu
cls
echo 标题:「 %tle% 」
echo ---------------------------------------
echo 菜单:
echo       ①  手动设置 Teredo 服务器
echo.
echo       ②  查看 Teredo 隧道状态
echo.
echo       Ｑ  退出
echo.
echo ---------------------------------------
if %var% neq 0 echo (输入无效请重新输入)
Set choice=
Set /p choice=选择: 
Set "choice=%choice:"=%"
if "%choice:~-1%"=="=" Goto Menu
if "%choice%"=="" Goto Menu
if /i "%choice%" == "1" cls&Goto ManuTeredo
if /i "%choice%" == "2" cls&Goto ShowState
if /i "%choice%" == "q" Popd&Exit
Set var=1
Goto Menu


:ShowState
Color 3e
MODE con: Cols=56 Lines=23
netsh interface teredo show state
echo.&Pause
Goto End

:ManuTeredo
Color 3f
MODE con: Cols=40 Lines=27
Set tle2=手动设置 Teredo 服务器
Set var2=0
Set manu1=win10.ipv6.microsoft.com.
Set manu2=teredo2.remlab.net.
Set manu3=win1710.ipv6.microsoft.com.
Set manu4=teredo-debian.remlab.net.
Set manu5=teredo.ginzado.ne.jp.
Set manu6=teredo.iks-jena.de.
Set manu7=teredo.ngix.ne.kr.
Set manu8=teredo.autotrans.consulintel.com.
Set manu9=teredo.managemydedi.com.
Set manu10=teredo.trex.fi.
Set manu11=debian-miredo.progsoc.org.
:Menu2
cls
echo 标题:「 %tle2% 」
echo ---------------------------------------
echo 菜单:
echo       ①  %manu1%
echo.
echo       ②  %manu2%
echo.
echo       ③  %manu3%
echo.
echo       ④  %manu4%
echo.
echo       ⑤  %manu5%
echo.
echo       ⑥  %manu6%
echo.
echo       ⑦  %manu7%
echo.
echo       ⑧  %manu8%
echo.
echo       ⑨  %manu9%
echo.
echo       ⑩  %manu10%
echo.
echo       11 %manu11% 
echo.
echo       Ｂ  返回主菜单
echo.
echo ---------------------------------------
if %var2% neq 0 echo (输入无效请重新输入)
Set choice2=
Set /p choice2=选择: 
Set "choice2=%choice2:"=%"
if "%choice2:~-1%"=="=" Goto Menu2
if "%choice2%"=="" Goto Menu2
if /i "%choice2%" == "1" cls&Goto TeredoSet
if /i "%choice2%" == "2" cls&Goto TeredoSet
if /i "%choice2%" == "3" cls&Goto TeredoSet
if /i "%choice2%" == "4" cls&Goto TeredoSet
if /i "%choice2%" == "5" cls&Goto TeredoSet
if /i "%choice2%" == "6" cls&Goto TeredoSet
if /i "%choice2%" == "7" cls&Goto TeredoSet
if /i "%choice2%" == "8" cls&Goto TeredoSet
if /i "%choice2%" == "9" cls&Goto TeredoSet
if /i "%choice2%" == "10" cls&Goto TeredoSet
if /i "%choice2%" == "11" cls&Goto TeredoSet
if /i "%choice2%" == "b" cls&Goto Start
if /i "%choice2%" == "q" Popd&Exit
Set var2=1
Goto Menu2
:TeredoSet
setlocal enabledelayedexpansion
netsh interface teredo set state server=!manu%choice2%!
endlocal
Goto End

:End
if "%choice%" neq "" (
    cls
    Color 2e
    MODE con: Cols=40 Lines=23
    if "%choice%" neq "3" (
        echo 操作完成 !!!
        if exist %WINDIR%\System32\timeout.exe (timeout /t 2) else (if exist %WINDIR%\System32\choice.exe (choice /t 2 /d y /n >nul) else (ping 127.1 -n 2 >nul))
    )
    Goto Start
)