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

REM 判断输入参数
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
echo       ⑴  启用 IPv6  √
echo.
echo       ⑵  禁用 IPv6  メ
echo.
echo       ⑶  查看 Teredo 隧道状态
echo.
echo       ⑷  手动设置 Teredo 服务器
echo.
echo       ⑸  自动设置 Teredo 服务器
echo.
echo       ⑹  电脑休眠 -^> IPv6 Fail 处理
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
if /i "%choice%" == "1" cls&Goto EnableIPv6
if /i "%choice%" == "2" cls&Goto DisableIPv6
if /i "%choice%" == "3" cls&Goto ShowState
if /i "%choice%" == "4" cls&Goto ManuTeredo
if /i "%choice%" == "5" cls&Goto AutoTeredo
if /i "%choice%" == "6" cls&Goto Ipv6FailProc
if /i "%choice%" == "r" cls&Goto RestTeredo
if /i "%choice%" == "q" Popd&Exit
Set var=1
Goto Menu

:EnableIPv6
echo 正在启用 IPv6，请稍后。。。
MODE con: Cols=88 Lines=32
sc config RpcEptMapper start= auto
sc start RpcEptMapper
sc config DcomLaunch start= auto
sc start DcomLaunch
sc config RpcSs start= auto
sc start RpcSs
sc config nsi start= auto
sc start nsi
sc config Winmgmt start= auto
sc start Winmgmt
sc config Dhcp start= auto
sc start Dhcp
sc config WinHttpAutoProxySvc start= auto
sc start WinHttpAutoProxySvc
sc config iphlpsvc start= auto
sc start iphlpsvc

netsh int ipv6 reset
netsh int teredo set state default
netsh int 6to4 set state default
netsh int isatap set state default
netsh int teredo set state server=teredo.remlab.net.
netsh int ipv6 set teredo enterpriseclient
netsh int ter set state enterpriseclient
route delete ::/0
netsh int ipv6 add route ::/0 "Teredo Tunneling Pseudo-Interface"
netsh int ipv6 set prefix 2002::/16 30 1
netsh int ipv6 set prefix 2001::/32 5 1

reg add HKLM\SYSTEM\CurrentControlSet\services\Dnscache\Parameters /v AddrConfigControl /t REG_DWORD /d 0 /f
reg add HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters /v DisabledComponents /t REG_DWORD /d 0 /f

netsh int teredo set state default
netsh int 6to4 set state default
netsh int isatap set state default
netsh int teredo set state server=teredo.remlab.net.
netsh int ipv6 set teredo enterpriseclient
netsh int ter set state enterpriseclient
route delete ::/0
netsh int ipv6 add route ::/0 "Teredo Tunneling Pseudo-Interface"
netsh int ipv6 set prefix 2002::/16 30 1
netsh int ipv6 set prefix 2001::/32 5 1
reg add HKLM\SYSTEM\CurrentControlSet\services\Dnscache\Parameters /v AddrConfigControl /t REG_DWORD /d 0 /f

ipconfig /flushdns

:: >%TEMP%\ipv6-state.txt ipconfig /all
:: >>%TEMP%\ipv6-state.txt netsh int ipv6 show teredo
:: >>%TEMP%\ipv6-state.txt netsh int ipv6 show route
:: >>%TEMP%\ipv6-state.txt netsh int ipv6 show int
:: >>%TEMP%\ipv6-state.txt netsh int ipv6 show prefix
:: >>%TEMP%\ipv6-state.txt netsh int ipv6 show address
:: >>%TEMP%\ipv6-state.txt route print
:: @start "" notepad.exe %TEMP%\ipv6-state.txt
:: if exist %WINDIR%\System32\choice.exe (choice /t 2 /d y /n >nul) else (ping 127.1 -n 5 >nul)
:: del /q %TEMP%\ipv6-state.txt 1>nul 2>nul
Goto End

:DisableIPv6
echo 正在禁用 IPv6，请稍后。。。
netsh interface teredo set state disable 1>nul 2>nul
netsh interface 6to4 set state disabled 1>nul 2>nul
netsh interface isatap set state disabled 1>nul 2>nul
Goto End

:ShowState
Color 3e
MODE con: Cols=56 Lines=23
netsh interface teredo show state
echo.&Pause
Goto End

:ManuTeredo
Color 3f
MODE con: Cols=45 Lines=27
:: MODE con: Cols=45 Lines=41
Set tle2=手动设置 Teredo 服务器
Set var2=0
Set manu1=teredo.remlab.net
Set manu2=teredo-debian.remlab.net
Set manu3=teredo.iks-jena.de


:Menu2
cls
echo 标题:「 %tle2% 」
echo --------------------------------------------
echo 菜单:
echo       ⑴  %manu1%
echo.
echo       ⑵  %manu2%
echo.
echo       ⑶  %manu3%
echo.
echo       Ｂ  返回主菜单
echo.
echo --------------------------------------------
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
:: if /i "%choice2%" == "9" cls&Goto TeredoSet
:: if /i "%choice2%" == "10" cls&Goto TeredoSet
:: if /i "%choice2%" == "11" cls&Goto TeredoSet
:: if /i "%choice2%" == "12" cls&Goto TeredoSet
:: if /i "%choice2%" == "13" cls&Goto TeredoSet
:: if /i "%choice2%" == "14" cls&Goto TeredoSet
:: if /i "%choice2%" == "15" cls&Goto TeredoSet
if /i "%choice2%" == "b" cls&Goto Start
if /i "%choice2%" == "q" Popd&Exit
Set var2=1
Goto Menu2
:TeredoSet
setlocal enabledelayedexpansion
netsh interface teredo set state server=!manu%choice2%!.
endlocal
Goto End

:AutoTeredo
Title 正在自动设置 Teredo 服务器，请稍后。。。
MODE con: Cols=88 Lines=32
REM 指定待搜索的文件
Set "fileName=python.exe"
for /r code %%a in (*%fileName%) do if /i "%%~nxa" equ "%fileName%" Set "pythonPath=%%a"
for /r ..\code %%a in (*%fileName%) do if /i "%%~nxa" equ "%fileName%" Set "pythonPath=%%a"
if "%pythonPath%" neq "" (
    Color 07
    "%pythonPath%" "%~dp0pteredor.py"
    Title CMD
    Goto End
) else (
    Color 04
    echo 找不到 %filename% 文件 !!!&echo.&Pause
    Title CMD
    Goto Start
)

:RestTeredo
echo 正在恢复默认 Teredo 服务器，请稍后。。。
netsh interface teredo set state enterpriseclient server=default
Goto End

:Ipv6FailProc
echo 正在处理 IPv6 状态 Fail，请稍后。。。
echo.&echo ① 先禁用上网网卡
:: control ncpa.cpl
control netconnections
echo.&echo ② 然后再启用上网网卡后，按任意键继续
Pause>nul
echo.&echo ③ 正在重启 IPv6 服务，请稍后。。。
sc config iphlpsvc start= auto 1>nul 2>nul
if exist %WINDIR%\System32\choice.exe (choice /t 1 /d y /n >nul) else (ping 127.1 -n 2 >nul)
sc query iphlpsvc | %WINDIR%\System32\findstr "STOPPED" 1>nul 2>nul
if '%ERRORLEVEL%' == '0' (
    sc start iphlpsvc 1>nul 2>nul
) else (
    sc stop iphlpsvc 1>nul 2>nul
    if exist %WINDIR%\System32\choice.exe (choice /t 1 /d y /n >nul) else (ping 127.1 -n 2 >nul)
    sc start iphlpsvc 1>nul 2>nul
)
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