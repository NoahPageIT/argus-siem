' Argus SIEM — server boot launcher (auto-start at logon, no window)
Set objShell = CreateObject("WScript.Shell")
' Free port 3001 if a stale instance holds it
objShell.Run "powershell -WindowStyle Hidden -Command ""$p = Get-NetTCPConnection -LocalPort 3001 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess; if($p){Stop-Process -Id $p -Force -ErrorAction SilentlyContinue}""", 0, True
' Start the Argus server hidden
objShell.Run "cmd /c node ""C:\Users\mediabox\Projects\argus-siem\server.js""", 0, False
