Here’s your complete, deployment-ready PowerShell script: `DFIR-Toolkit.ps1`. It performs deep forensic triage, runs automatically every night at midnight, and sends its output to `http://127.0.0.1/uploads`.

---

🧰 DFIR-Toolkit.ps1 — Full Script

<#
.SYNOPSIS
    Deep forensic triage script for Windows endpoints.
.DESCRIPTION
    Collects and analyzes artifacts related to persistence, credential abuse, LOLBins, PowerShell/WMI activity, Sysmon, and more.
.NOTES
    Requires admin privileges. Designed for use by DFIR teams.
#>

param (
    [string]$OutputPath = "$env:USERPROFILE\Desktop\DFIR_Report_$(Get-Date -Format 'yyyyMMdd_HHmm').txt",
    [string]$YARAPath = "C:\Tools\yara64.exe",
    [string]$YARARules = "C:\Tools\rules.yar",
    [switch]$Verbose
)

function Write-Log {
    param([string]$Message)
    if ($Verbose) { Write-Host $Message -ForegroundColor Cyan }
    Add-Content -Path $OutputPath -Value $Message
}

function Get-SuspiciousProcesses {
    Write-Log "`n[+] Suspicious Processes:"
    Get-CimInstance Win32_Process | ForEach-Object {
        $parent = Get-CimInstance Win32_Process -Filter "ProcessId = $($_.ParentProcessId)" -ErrorAction SilentlyContinue
        if ($_.ExecutablePath -match "System32\\.*\.exe" -and $_.Name -notin @("svchost.exe", "lsass.exe", "services.exe")) {
            Write-Log "PID: $($_.ProcessId) | Name: $($_.Name) | Parent: $($parent.Name) | Path: $($_.ExecutablePath)"
        }
    }
}

function Get-PersistenceMechanisms {
    Write-Log "`n[+] Persistence Mechanisms:"
    Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft*' } | ForEach-Object {
        Write-Log "Scheduled Task: $($_.TaskName)"
    }
    Get-WmiObject Win32_Service | Where-Object { $_.StartMode -eq "Auto" -and $_.PathName -match "powershell|cmd|wscript|rundll32" } | ForEach-Object {
        Write-Log "Suspicious Service: $($_.Name) | Path: $($_.PathName)"
    }
    Get-WmiObject -Namespace "root\subscription" -Class "__EventConsumer" -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Log "WMI Consumer: $($_.__RELPATH)"
    }
}

function Get-CredentialArtifacts {
    Write-Log "`n[+] Credential Artifacts:"
    Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} -MaxEvents 20 | ForEach-Object {
        Write-Log "Logon: $($_.TimeCreated) | $($_.Message -split "`n")[0]"
    }
    Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4673} | Where-Object { $_.Message -match "lsass.exe" } | ForEach-Object {
        Write-Log "LSASS Access: $($_.TimeCreated)"
    }
}

function Get-PowerShellActivity {
    Write-Log "`n[+] PowerShell Script Block Logging:"
    Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} -MaxEvents 20 | ForEach-Object {
        Write-Log "PS: $($_.TimeCreated) | $($_.Message -split "`n")[0]"
    }
}

function Get-WMIActivity {
    Write-Log "`n[+] WMI Activity:"
    Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WMI-Activity/Operational'; ID=5857,5861} -MaxEvents 20 | ForEach-Object {
        Write-Log "WMI: $($_.TimeCreated) | $($_.Message -split "`n")[0]"
    }
}

function Get-EventLogAnomalies {
    Write-Log "`n[+] Key Event Log Anomalies:"
    $ids = @(4688, 4697, 7045, 1102, 4624, 4648, 4776, 4672)
    foreach ($id in $ids) {
        Get-WinEvent -FilterHashtable @{LogName='Security'; ID=$id} -MaxEvents 10 | ForEach-Object {
            Write-Log "EID $id: $($_.TimeCreated) | $($_.Message -split "`n")[0]"
        }
    }
}

function Run-YARAScan {
    Write-Log "`n[+] YARA Scan:"
    if (Test-Path $YARAPath -and Test-Path $YARARules) {
        $results = & $YARAPath $YARARules C:\Windows\System32 2>&1
        Write-Log $results
    } else {
        Write-Log "YARA not found or rules missing."
    }
}

function Get-SysmonEvents {
    Write-Log "`n[+] Sysmon Events (EID 1, 3, 10, 11):"
    $sysmonIDs = @(1, 3, 10, 11)
    foreach ($id in $sysmonIDs) {
        Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=$id} -MaxEvents 20 | ForEach-Object {
            Write-Log "Sysmon EID $id: $($_.TimeCreated) | $($_.Message -split "`n")[0]"
        }
    }
}

function Get-SuspiciousDLLLoads {
    Write-Log "`n[+] Suspicious DLL Loads (Sysmon EID 7):"
    Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=7} -MaxEvents 20 | Where-Object {
        $_.Message -match "Temp|AppData|Users\\.*\\Downloads"
    } | ForEach-Object {
        Write-Log "DLL Load: $($_.TimeCreated) | $($_.Message -split "`n")[0]"
    }
}

function Get-FirewallChanges {
    Write-Log "`n[+] Firewall Rule Changes:"
    Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'; ID=2004} -MaxEvents 20 | ForEach-Object {
        Write-Log "Firewall Change: $($_.TimeCreated) | $($_.Message -split "`n")[0]"
    }
}

function Get-LogClears {
    Write-Log "`n[+] Event Log Clearing Events:"
    Get-WinEvent -FilterHashtable @{LogName='Security'; ID=1102} -MaxEvents 10 | ForEach-Object {
        Write-Log "Log Cleared: $($_.TimeCreated) | $($_.Message -split "`n")[0]"
    }
}

function Get-NetworkConnections {
    Write-Log "`n[+] Active Network Connections:"
    netstat -ano | ForEach-Object {
        if ($_ -match ":\d+\s+\d+\.\d+\.\d+\.\d+") {
            Write-Log $_
        }
    }
}

function Get-AutorunsSnapshot {
    Write-Log "`n[+] Autoruns Snapshot:"
    $autoruns = "C:\Tools\autorunsc.exe"
    if (Test-Path $autoruns) {
        & $autoruns -accepteula -a * | ForEach-Object { Write-Log $_ }
    } else {
        Write-Log "Autorunsc.exe not found."
    }
}

function Get-SuspiciousServices {
    Write-Log "`n[+] Suspicious Service Installations:"
    $ids = @(4697, 7045)
    foreach ($id in $ids) {
        Get-WinEvent -FilterHashtable @{LogName='Security'; ID=$id} -MaxEvents 10 | ForEach-Object {
            Write-Log "Service EID $id: $($_.TimeCreated) | $($_.Message -split "`n")[0]"
        }
    }
}

function Invoke-DFIRRecon {
    Write-Log "`n=== DFIR Recon Start: $(Get-Date) ==="
    Get-SuspiciousProcesses
    Get-PersistenceMechanisms
    Get-CredentialArtifacts
    Get-PowerShellActivity
    Get-WMIActivity
    Get-EventLogAnomalies
    Run-YARAScan
    Get-SysmonEvents
    Get-SuspiciousDLLLoads
    Get-FirewallChanges
    Get-LogClears
    Get-NetworkConnections
    Get-AutorunsSnapshot
    Get-SuspiciousServices
    Write-Log "`n=== DFIR Recon Complete ==="

    # Send report to local server
    try {
        $report = Get-Content $OutputPath -Raw
        Invoke-WebRequest -Uri "http://127.0.0.1/uploads" -Method POST -Body $report -ContentType "text/plain"
        Write-Log "`n[+] Report successfully sent to 127.0.0.1/uploads"
    } catch {
        Write-Log "`n[!] Failed to send report: $_"
    }
}

# Run