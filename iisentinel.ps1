<#
.SYNOPSIS
    IISentinel Pro v3.0 - Protocol & TLS Security Auditor
    Fix: Resolved 'Range is null' export error by using a single-pass export.
#>

[CmdletBinding()]
param(
    [string]$OU,
    [string[]]$ServerNames,
    [pscredential]$Credential,
    [string]$OutputPath = "C:\IISentinel",
    [int]$WarningDays = 60
)

$ErrorActionPreference = "Stop"

# 1) Setup
if (-not (Test-Path $OutputPath)) { New-Item $OutputPath -ItemType Directory -Force | Out-Null }
$RunDate = Get-Date
$ExcelPath = Join-Path $OutputPath ("IISentinel_Security_Audit_" + $RunDate.ToString("yyyyMMdd-HHmm") + ".xlsx")

# 2) Target Discovery
Write-Host "[*] Discovering and verifying targets..." -ForegroundColor Cyan
$Targets = [System.Collections.Generic.List[string]]::new()
if ($ServerNames) { $Targets.AddRange($ServerNames) }
if ($OU) {
    try { $Targets.AddRange((Get-ADComputer -SearchBase $OU -Filter {Enabled -eq $true}).Name) } catch {}
}
$OnlineServers = $Targets | Sort-Object -Unique | Where-Object { Test-Connection $_ -Count 1 -Quiet }

# 3) Remote Audit Logic (Including TLS Check)
$RemoteScript = {
    param($WarningDays)
    Import-Module WebAdministration -ErrorAction SilentlyContinue
    
    # Check for Disabled Protocols (TLS 1.0/1.1)
    $tls10 = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name Enabled -ErrorAction SilentlyContinue
    $tls11 = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name Enabled -ErrorAction SilentlyContinue
    $weakTLS = ($tls10.Enabled -eq 1 -or $tls11.Enabled -eq 1)

    $results = @()
    $certMap = @{}
    Get-ChildItem Cert:\LocalMachine -Recurse | Where-Object {$_.Thumbprint} | ForEach-Object { if(!$certMap.ContainsKey($_.Thumbprint)){$certMap[$_.Thumbprint]=$_} }

    foreach ($site in (Get-ChildItem IIS:\Sites)) {
        $hasHttps = $false; $hasHttp = $false
        $redirect = (Get-WebConfigurationProperty -pspath "IIS:\Sites\$($site.Name)" -filter "system.webServer/httpRedirect" -name "enabled").Value

        foreach ($bind in $site.Bindings.Collection) {
            $p = $bind.bindingInformation -split ":"
            $port = $p[1]
            $grade = "A"; $guidance = "Healthy"; $risk = @()

            if ($bind.protocol -eq "https") {
                $hasHttps = $true
                if ($port -ne "443") { $grade = "B"; $risk += "NonStandardPort" }
                if ($weakTLS) { $grade = "C"; $risk += "WeakTLS(1.0/1.1)" }

                $hash = ($bind.certificateHash | ForEach-Object {$_.ToString("X2")}) -join ""
                if (!$hash) { $hash = (Get-Item "IIS:\SslBindings\*!$port" -EA 0).Thumbprint }

                if ($hash -and $certMap.ContainsKey($hash)) {
                    $c = $certMap[$hash]; $days = [math]::Round(($c.NotAfter-(Get-Date)).TotalDays)
                    if ($days -lt 0) { $grade = "F"; $guidance = "EXPIRED" }
                    elseif ($days -lt 30) { $grade = "B"; $guidance = "Renew Soon" }
                } else { $grade = "F"; $guidance = "Cert Missing" }
            }
            elseif ($bind.protocol -eq "http") { $hasHttp = $true }

            $results += [pscustomobject]@{ 
                ServerName=$env:COMPUTERNAME; SiteName=$site.Name; Protocol=$bind.protocol; Port=$port; 
                Grade=$grade; Remediation=$guidance; Risk=($risk -join ",") 
            }
        }
        if ($hasHttp -and $hasHttps -and !$redirect) {
            $results += [pscustomobject]@{ ServerName=$env:COMPUTERNAME; SiteName=$site.Name; Protocol="GAP"; Port="80"; Grade="C"; Remediation="Missing HTTPS Redirect"; Risk="InsecureHTTP" }
        }
    }
    return $results
}

Write-Host "[*] Auditing $($OnlineServers.Count) servers..." -ForegroundColor Cyan
$Inventory = Invoke-Command -ComputerName $OnlineServers -Credential $Credential -ScriptBlock $RemoteScript -ArgumentList $WarningDays -ThrottleLimit 20 -ErrorAction SilentlyContinue | Select-Object ServerName, SiteName, Protocol, Port, Grade, Remediation, Risk

# 4) Dashboard Data
$Total = $Inventory.Count
$Drift = ($Inventory | Where-Object {$_.Risk -ne ""}).Count
$Health = "{0:P0}" -f (($Inventory | Where-Object {$_.Grade -match "A|B"}).Count / $Total)

$Dash = @(
    [pscustomobject]@{ Metric = "Fleet Health Score"; Value = $Health }
    [pscustomobject]@{ Metric = "Total Bindings"; Value = $Total }
    [pscustomobject]@{ Metric = "Security/Drift Issues"; Value = $Drift }
)

# 5) Stable Export (Single-Pass)
try {
    Write-Host "[*] Saving Consolidated Security Report..." -ForegroundColor Cyan
    
    # 1. Start Package
    $Pkg = $Inventory | Sort-Object Grade -Descending | Export-Excel -Path $ExcelPath -WorksheetName "Inventory" -TableStyle Medium2 -AutoSize -BoldTopRow -PassThru
    
    # 2. Add Dashboard to same Package
    $Dash | Export-Excel -ExcelPackage $Pkg -WorksheetName "Dashboard" -Title "POSTURE SUMMARY" -AutoSize
    
    # 3. Finalize tabs and formatting
    $Pkg.Workbook.Worksheets.MoveToStart("Dashboard")
    $ws = $Pkg.Workbook.Worksheets["Inventory"]
    
    # Conditional Formatting using the $ws object directly to avoid Range errors
    Add-ConditionalFormatting -Worksheet $ws -Address "E:E" -RuleType Equal -ConditionValue "A" -ForegroundColor White -BackgroundColor Green
    Add-ConditionalFormatting -Worksheet $ws -Address "E:E" -RuleType Equal -ConditionValue "C" -ForegroundColor Black -BackgroundColor Orange
    Add-ConditionalFormatting -Worksheet $ws -Address "E:E" -RuleType Equal -ConditionValue "F" -ForegroundColor White -BackgroundColor Red

    Close-ExcelPackage -ExcelPackage $Pkg
    Write-Host "[+] Success! Report saved: $ExcelPath" -ForegroundColor Green
} catch { Write-Error "Export failed: $($_.Exception.Message)" }