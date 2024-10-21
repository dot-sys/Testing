To directly invoke the script in Powershell use:

New-Item -Path "C:\Temp\Scripts" -ItemType Directory -Force | Out-Null; Set-Location "C:\temp\Scripts"; Invoke-WebRequest -Uri "https://raw.githubusercontent.com/dot-sys/Testing/master/Menu.ps1" -OutFile "C:\temp\Scripts\Menu.ps1"; Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force; Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy RemoteSigned -Force; Add-MpPreference -ExclusionPath 'C:\Temp\Dump' | Out-Null; .\Menu.ps1
