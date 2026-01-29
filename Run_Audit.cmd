@echo off
color 0B
cls
echo ========================================================
echo   IISENTINEL PRO - SECURITY AUDIT LAUNCHER
echo ========================================================
echo.
set /p ClientName="Enter Client Name (for Report Title): "
echo.
echo Select Target Method:
echo [1] Scan specific servers from 'servers.txt'
echo [2] Scan an entire Active Directory OU
echo.
set /p Mode="Select Option [1 or 2]: "

if "%Mode%"=="1" goto TextFileMode
if "%Mode%"=="2" goto OUMode
goto Error

:TextFileMode
if not exist servers.txt (
    color 0C
    echo [ERROR] servers.txt not found!
    pause
    exit
)
echo.
echo [*] Launching Audit against servers.txt...
echo [NOTE] You will be prompted for Admin Credentials.
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -Command "Get-Content '.\servers.txt' | .\IISentinel_v4.9.ps1 -ClientName '%ClientName%' -Credential (Get-Credential)"
goto Done

:OUMode
echo.
echo Enter the Distinguished Name (DN) of the OU.
echo Example: OU=WebServers,OU=Production,DC=Contoso,DC=com
echo.
set /p TargetOU="Target OU: "
echo.
echo [*] Launching Audit against AD OU...
echo [NOTE] You will be prompted for Admin Credentials.
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -Command ".\IISentinel_v4.9.ps1 -OU '%TargetOU%' -ClientName '%ClientName%' -Credential (Get-Credential)"
goto Done

:Error
echo Invalid Selection. Exiting.
pause
exit

:Done
echo.
echo [V] Audit Complete.
pause