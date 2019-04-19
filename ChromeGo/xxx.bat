:loop
ipconfig /flushdns
netsh int teredo show state
ping 127.0.0.1 > null
goto loop