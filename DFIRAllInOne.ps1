# Comprehensive PowerShell Incident Response Script - Extended Version
# Date: October 13, 2025
# Purpose: This script automates the collection of forensic artifacts, system information, logs, and other data
# to assist an Incident Response team. It includes features for system info, logs, processes, network, persistence,
# credentials, memory, malware, timeline, browser, USB, firewall, custom collections, cloud artifacts, password audit,
# SMB analysis, event log analysis, volatility preparation, AI prompts, and response reporting. Additional extensions
# cover registry analysis, file system examination, volume shadow copies, file carving, string searching, and more.
# 
# WARNING: Run this script with administrative privileges. It may generate large amounts of data.
# Output is saved to a directory named "IR_Collection_[Timestamp]" in the current path.
# 
# Usage: .\IR_Script_Extended.ps1 [-OutputDir ] [-Modules ] [-Verbose]
# Modules: All (default), SystemInfo, Logs, Processes, Network, Persistence, Credentials, Memory, Malware, Timeline, 
# Browser, USB, Firewall, Custom, Cloud, PasswordAudit, SMB, EventAnalysis, VolatilityPrep, AI_Prompts, Response_Report,
# Registry, FileSystem, VSS, Carving, StringSearch, DiskEncryption, UserProfiling, NetworkHistory, InstalledApps, Autostart
#
# This script is extended with additional forensic collection capabilities for deeper analysis.

param (
    [string]$OutputDir = (Join-Path -Path $PWD -ChildPath "IR_Collection_$(Get-Date -Format 'yyyyMMdd_HHmmss')"),
    [string]$Modules = "All",
    [switch]$Verbose
)

# Global Variables
$ScriptVersion = "3.0.0 - Extended"
$HostName = $env:COMPUTERNAME
$LogFile = Join-Path -Path $OutputDir -ChildPath "IR_Script_Log.txt"
$ErrorLog = Join-Path -Path $OutputDir -ChildPath "IR_Script_Errors.txt"

# Ensure Output Directory Exists
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}

# Logging Function with Millisecond Precision
function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $LogEntry = "$Timestamp [$Level] [$HostName] $Message"
    $LogEntry | Out-File -FilePath $LogFile -Append -Encoding utf8
    if ($Verbose) { Write-Host $LogEntry }
}

# Error Handling Function with Full Exception Details
function Handle-Error {
    param (
        [string]$Message,
        [Exception]$Exception
    )
    $ErrorDetails = "ERROR: $Message - $($Exception.Message) - StackTrace: $($Exception.StackTrace) - TargetSite: $($Exception.TargetSite)"
    Write-Log -Message $ErrorDetails -Level "ERROR"
    $ErrorDetails | Out-File -FilePath $ErrorLog -Append -Encoding utf8
}

Write-Log "Script started on $HostName. Version: $ScriptVersion"

# Extended Module List
$AllModules = @("SystemInfo", "Logs", "Processes", "Network", "Persistence", "Credentials", "Memory", "Malware", "Timeline", 
                "Browser", "USB", "Firewall", "Custom", "Cloud", "PasswordAudit", "SMB", "EventAnalysis", "VolatilityPrep", 
                "AI_Prompts", "Response_Report", "Registry", "FileSystem", "VSS", "Carving", "StringSearch", "DiskEncryption", 
                "UserProfiling", "NetworkHistory", "InstalledApps", "Autostart")
$SelectedModules = if ($Modules -eq "All") { $AllModules } else { $Modules -split "," }

# Helper Function: Check Tool Availability
function Check-Tool {
    param (
        [string]$ToolPath
    )
    if (Test-Path $ToolPath) {
        return $true
    } else {
        Write-Log "Tool at $ToolPath not found. Skipping related operations." -Level "WARNING"
        return $false
    }
}

# Helper Function: Safe Export to CSV
function Safe-ExportCsv {
    param (
        [object]$Data,
        [string]$Path
    )
    try {
        $Data | Export-Csv -Path $Path -NoTypeInformation -Encoding utf8 -ErrorAction Stop
    } catch {
        Handle-Error -Message "Failed to export CSV to $Path" -Exception $_
    }
}

# Helper Function: Safe Copy Item
function Safe-CopyItem {
    param (
        [string]$Source,
        [string]$Destination
    )
    try {
        Copy-Item -Path $Source -Destination $Destination -Recurse -ErrorAction Stop
    } catch {
        Handle-Error -Message "Failed to copy from $Source to $Destination" -Exception $_
    }
}

# Function to Collect System Information
function Collect-SystemInfo {
    try {
        Write-Log "Collecting System Information..."
        $SysInfoFile = Join-Path -Path $OutputDir -ChildPath "SystemInfo.txt"
        
        Get-ComputerInfo | Out-File -FilePath $SysInfoFile -Encoding utf8
        
        Get-WmiObject -Class Win32_OperatingSystem | Select-Object * | Out-File -FilePath $SysInfoFile -Append -Encoding utf8
        
        Get-WmiObject -Class Win32_ComputerSystem | Select-Object * | Out-File -FilePath $SysInfoFile -Append -Encoding utf8
        
        Get-LocalUser | Select-Object * | Out-File -FilePath $SysInfoFile -Append -Encoding utf8
        
        Get-LocalGroup | ForEach-Object {
            $group = $_
            Get-LocalGroupMember -Group $group.Name | Select-Object @{Name='Group'; Expression={$group.Name}}, *
        } | Safe-ExportCsv -Path (Join-Path -Path $OutputDir -ChildPath "LocalGroups.csv")
        
        Get-WmiObject -Class Win32_Product | Select-Object * | Sort-Object Name | Out-File -FilePath $SysInfoFile -Append -Encoding utf8
        
        Get-HotFix | Select-Object * | Sort-Object InstalledOn -Descending | Out-File -FilePath $SysInfoFile -Append -Encoding utf8
        
        Get-ChildItem Env: | Sort-Object Name | Out-File -FilePath (Join-Path -Path $OutputDir -ChildPath "EnvironmentVariables.txt") -Encoding utf8
        
        Write-Log "System Information collected."
    } catch {
        Handle-Error -Message "Failed to collect System Info" -Exception $_
    }
}

# Function to Collect Event Logs
function Collect-Logs {
    try {
        Write-Log "Collecting Event Logs..."
        $LogsDir = Join-Path -Path $OutputDir -ChildPath "Logs"
        if (-not (Test-Path $LogsDir)) { New-Item -ItemType Directory -Path $LogsDir | Out-Null }
        
        wevtutil epl Security "$LogsDir\Security.evtx" /q:*[System[(Level=1 or Level=2 or Level=3)]]
        wevtutil epl System "$LogsDir\System.evtx"
        wevtutil epl Application "$LogsDir\Application.evtx"
        
        wevtutil epl "Microsoft-Windows-PowerShell/Operational" "$LogsDir\PowerShell_Operational.evtx"
        wevtutil epl "Microsoft-Windows-WMI-Activity/Operational" "$LogsDir\WMI_Activity.evtx"
        
        wevtutil epl "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational" "$LogsDir\RDP.evtx"
        wevtutil epl "Microsoft-Windows-TaskScheduler/Operational" "$LogsDir\TaskScheduler.evtx"
        
        wevtutil epl "Microsoft-Windows-Windows Defender/Operational" "$LogsDir\Defender.evtx" -ErrorAction SilentlyContinue
        wevtutil epl "Microsoft-Windows-Sysmon/Operational" "$LogsDir\Sysmon.evtx" -ErrorAction SilentlyContinue
        
        $suspEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624,4625,4648,4672,4720,4776,1102,4740} -MaxEvents 5000 -ErrorAction SilentlyContinue
        Safe-ExportCsv -Data $suspEvents -Path "$LogsDir\Suspicious_Events.csv"
        
        $acctEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4720,4722,4724,4732,4738,4740} -MaxEvents 2000 -ErrorAction SilentlyContinue
        Safe-ExportCsv -Data $acctEvents -Path "$LogsDir\Account_Management.csv"
        
        $svcEvents = Get-WinEvent -FilterHashtable @{LogName='System'; ID=7036,7045,7040,7034} -MaxEvents 2000 -ErrorAction SilentlyContinue
        Safe-ExportCsv -Data $svcEvents -Path "$LogsDir\Service_Changes.csv"
        
        $clearEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=1102,104} -MaxEvents 1000 -ErrorAction SilentlyContinue
        Safe-ExportCsv -Data $clearEvents -Path "$LogsDir\Log_Clearing.csv"
        
        Write-Log "Event Logs collected."
    } catch {
        Handle-Error -Message "Failed to collect Logs" -Exception $_
    }
}

# Function to Collect Process Information
function Collect-Processes {
    try {
        Write-Log "Collecting Process Information..."
        $ProcDir = Join-Path -Path $OutputDir -ChildPath "Processes"
        if (-not (Test-Path $ProcDir)) { New-Item -ItemType Directory -Path $ProcDir | Out-Null }
        
        Get-Process | Select-Object * | Export-Csv -Path "$ProcDir\Processes.csv" -NoTypeInformation
        
        function Get-ProcessTreeRecursive {
            param (
                [int]$ProcessId = 0,
                [int]$Depth = 0,
                [string]$OutputFile
            )
            $procs = Get-CimInstance Win32_Process | Where-Object { $_.ParentProcessId -eq $ProcessId }
            foreach ($proc in $procs) {
                $indent = "  " * $Depth
                "$indent PID: $($proc.ProcessId) Name: $($proc.Name) CommandLine: $($proc.CommandLine) CreationDate: $($proc.CreationDate)" | Out-File -FilePath $OutputFile -Append -Encoding utf8
                Get-ProcessTreeRecursive -ProcessId $proc.ProcessId -Depth ($Depth + 1) -OutputFile $OutputFile
            }
        }
        Get-ProcessTreeRecursive -OutputFile "$ProcDir\ProcessTree.txt"
        
        $suspNames = @('rundll32', 'regsvr32', 'cmd', 'powershell', 'wscript', 'cscript', 'mshta', 'bitsadmin', 'certutil', 'installutil')
        Get-Process | Where-Object { $suspNames -contains $_.Name } | Export-Csv -Path "$ProcDir\Suspicious_Processes.csv" -NoTypeInformation
        
        Get-Process | ForEach-Object { $_.Modules | Select-Object @{Name='ProcessName'; Expression={$_.ProcessName}}, * } | Export-Csv -Path "$ProcDir\Process_Modules.csv" -NoTypeInformation
        
        Write-Log "Process Information collected."
    } catch {
        Handle-Error -Message "Failed to collect Processes" -Exception $_
    }
}

# Function to Collect Network Information
function Collect-Network {
    try {
        Write-Log "Collecting Network Information..."
        $NetDir = Join-Path -Path $OutputDir -ChildPath "Network"
        if (-not (Test-Path $NetDir)) { New-Item -ItemType Directory -Path $NetDir | Out-Null }
        
        netstat -ano -p tcp | Out-File -FilePath "$NetDir\Netstat_TCP.txt" -Encoding utf8
        netstat -ano -p udp | Out-File -FilePath "$NetDir\Netstat_UDP.txt" -Encoding utf8
        
        Get-NetTCPConnection | Select-Object * | Export-Csv -Path "$NetDir\TCP_Connections.csv" -NoTypeInformation
        
        Get-NetUDPEndpoint | Select-Object * | Export-Csv -Path "$NetDir\UDP_Endpoints.csv" -NoTypeInformation
        
        arp -a | Out-File -FilePath "$NetDir\ARP_Cache.txt" -Encoding utf8
        
        ipconfig /displaydns | Out-File -FilePath "$NetDir\DNS_Cache.txt" -Encoding utf8
        
        Get-NetRoute | Select-Object * | Export-Csv -Path "$NetDir\Routing_Table.csv" -NoTypeInformation
        
        Get-NetAdapter | Select-Object * | Export-Csv -Path "$NetDir\Network_Adapters.csv" -NoTypeInformation
        
        if (Check-Tool "pktmon.exe") {
            pktmon start --etw -p 0 -m real-time --comp nics --pkt-size 128 --log-mode circular --file-name "$NetDir\Pktmon.etl" --file-size 50
            Start-Sleep -Seconds 60
            pktmon stop
        }
        
        Write-Log "Network Information collected."
    } catch {
        Handle-Error -Message "Failed to collect Network" -Exception $_
    }
}

# Function to Collect Persistence Mechanisms
function Collect-Persistence {
    try {
        Write-Log "Collecting Persistence Information..."
        $PersistDir = Join-Path -Path $OutputDir -ChildPath "Persistence"
        if (-not (Test-Path $PersistDir)) { New-Item -ItemType Directory -Path $PersistDir | Out-Null }
        
        if (Check-Tool "autorunsc.exe") {
            autorunsc.exe -a * -c -h -s | Out-File -FilePath "$PersistDir\Autoruns.csv" -Encoding utf8
        } else {
            Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run*" | Out-File -FilePath "$PersistDir\Run_Registry.txt" -Encoding utf8
            Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce*" | Out-File -FilePath "$PersistDir\Run_Registry.txt" -Append -Encoding utf8
            Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run*" | Out-File -FilePath "$PersistDir\Run_Registry.txt" -Append -Encoding utf8
        }
        
        Get-Service | Select-Object * | Export-Csv -Path "$PersistDir\Services.csv" -NoTypeInformation
        
        Get-ScheduledTask | Select-Object * | Export-Csv -Path "$PersistDir\Scheduled_Tasks.csv" -NoTypeInformation
        
        Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer | Export-Csv -Path "$PersistDir\WMI_Consumers.csv" -NoTypeInformation
        Get-CimInstance -Namespace root\subscription -ClassName __EventFilter | Export-Csv -Path "$PersistDir\WMI_Filters.csv" -NoTypeInformation
        
        Get-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" -Recurse -ErrorAction SilentlyContinue | Out-File -FilePath "$PersistDir\Startup_Folders.txt" -Encoding utf8
        Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -Recurse -ErrorAction SilentlyContinue | Out-File -FilePath "$PersistDir\Startup_Folders.txt" -Append -Encoding utf8
        
        Get-ChildItem "C:\inetpub\wwwroot" -Recurse -Filter *.asp*,*.php,*.jsp -ErrorAction SilentlyContinue | Select-Object FullName, LastWriteTime | Export-Csv -Path "$PersistDir\Potential_Web_Shells.csv" -NoTypeInformation
        
        Write-Log "Persistence Information collected."
    } catch {
        Handle-Error -Message "Failed to collect Persistence" -Exception $_
    }
}

# Function to Collect Credential Artifacts
function Collect-Credentials {
    try {
        Write-Log "Collecting Credential Artifacts..."
        $CredDir = Join-Path -Path $OutputDir -ChildPath "Credentials"
        if (-not (Test-Path $CredDir)) { New-Item -ItemType Directory -Path $CredDir | Out-Null }
        
        Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue | Out-File -FilePath "$CredDir\LSA_Settings.txt" -Encoding utf8
        
        Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name CachedLogonsCount -ErrorAction SilentlyContinue | Out-File -FilePath "$CredDir\Cached_Logons.txt" -Encoding utf8
        
        klist sessions | Out-File -FilePath "$CredDir\Kerberos_Sessions.txt" -Encoding utf8
        klist tickets | Out-File -FilePath "$CredDir\Kerberos_Tickets.txt" -Encoding utf8
        
        Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name UseLogonCredential -ErrorAction SilentlyContinue | Out-File -FilePath "$CredDir\WDigest_Status.txt" -Encoding utf8
        
        Get-Process lsass -ErrorAction SilentlyContinue | Select-Object * | Out-File -FilePath "$CredDir\LSASS_Details.txt" -Encoding utf8
        
        Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name LsaCfgFlags -ErrorAction SilentlyContinue | Out-File -FilePath "$CredDir\Credential_Guard.txt" -Encoding utf8
        
        Safe-CopyItem -Source "C:\Windows\System32\config\SAM" -Destination "$CredDir\SAM"
        Safe-CopyItem -Source "C:\Windows\System32\config\SECURITY" -Destination "$CredDir\SECURITY"
        Safe-CopyItem -Source "C:\Windows\System32\config\SYSTEM" -Destination "$CredDir\SYSTEM"
        
        Write-Log "Credential Artifacts collected."
    } catch {
        Handle-Error -Message "Failed to collect Credentials" -Exception $_
    }
}

# Function to Collect Memory Artifacts
function Collect-Memory {
    try {
        Write-Log "Collecting Memory Artifacts..."
        $MemDir = Join-Path -Path $OutputDir -ChildPath "Memory"
        if (-not (Test-Path $MemDir)) { New-Item -ItemType Directory -Path $MemDir | Out-Null }
        
        Get-Process | Select-Object Id, Name, WorkingSet64, VirtualMemorySize64, PrivateMemorySize64, PagedMemorySize64 | Export-Csv -Path "$MemDir\Process_Memory_Stats.csv" -NoTypeInformation
        
        Get-CimInstance Win32_PageFileUsage | Out-File -FilePath "$MemDir\Pagefile_Usage.txt" -Encoding utf8
        
        powercfg /query | Out-File -FilePath "$MemDir\Power_Config.txt" -Encoding utf8
        
        if (Check-Tool "winpmem.exe") {
            .\winpmem.exe --format raw -o "$MemDir\memory.raw"
        } elseif (Check-Tool "DumpIt.exe") {
            .\DumpIt.exe /Q /O "$MemDir\memory.dmp"
        } elseif (Check-Tool "MagnetRAMCapture.exe") {
            .\MagnetRAMCapture.exe /accepteula /go /output "$MemDir"
        }
        
        Safe-CopyItem -Source "C:\hiberfil.sys" -Destination "$MemDir\hiberfil.sys"
        Safe-CopyItem -Source "C:\pagefile.sys" -Destination "$MemDir\pagefile.sys"
        Safe-CopyItem -Source "C:\swapfile.sys" -Destination "$MemDir\swapfile.sys"
        
        Write-Log "Memory Artifacts collected."
    } catch {
        Handle-Error -Message "Failed to collect Memory" -Exception $_
    }
}

# Function to Scan for Malware Indicators
function Collect-Malware {
    try {
        Write-Log "Scanning for Malware Indicators..."
        $MalDir = Join-Path -Path $OutputDir -ChildPath "Malware"
        if (-not (Test-Path $MalDir)) { New-Item -ItemType Directory -Path $MalDir | Out-Null }
        
        if (Check-Tool "sigcheck.exe") {
            .\sigcheck.exe -e -u -vr -vt -h C:\Windows\System32 | Out-File -FilePath "$MalDir\Sigcheck_System32.txt" -Encoding utf8
            .\sigcheck.exe -e -u -vr -vt -h C:\Windows\SysWOW64 | Out-File -FilePath "$MalDir\Sigcheck_SysWOW64.txt" -Encoding utf8
        }
        
        if (Check-Tool "yara64.exe") {
            .\yara64.exe -r -w rules.yar C:\ -p 4 | Out-File -FilePath "$MalDir\YARA_Scan.txt" -Encoding utf8
        }
        
        if (Check-Tool "capa.exe") {
            Get-ChildItem "C:\Windows\Temp","C:\Users\*\AppData\Local\Temp" -Filter *.exe -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                .\capa.exe -vv $_.FullName | Out-File -FilePath "$MalDir\Capa_$($_.Name).txt" -Encoding utf8
            }
        }
        
        $hashDirs = @("C:\Windows\System32", "C:\Windows\SysWOW64", "C:\Program Files")
        foreach ($dir in $hashDirs) {
            Get-ChildItem $dir -Recurse -File -ErrorAction SilentlyContinue | Get-FileHash -Algorithm SHA256,MD5 | Export-Csv -Path "$MalDir\Hashes_$(($dir -replace '\\|:', '_')).csv" -NoTypeInformation
        }
        
        if (Check-Tool "strings.exe") {
            Get-ChildItem "C:\Windows\Temp" -Filter *.dll,*.exe -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                .\strings.exe -n 8 $_.FullName | Out-File -FilePath "$MalDir\Strings_$($_.Name).txt" -Encoding utf8
            }
        }
        
        Write-Log "Malware Indicators collected."
    } catch {
        Handle-Error -Message "Failed to collect Malware" -Exception $_
    }
}

# Function to Create Timeline
function Collect-Timeline {
    try {
        Write-Log "Creating Timeline Artifacts..."
        $TimeDir = Join-Path -Path $OutputDir -ChildPath "Timeline"
        if (-not (Test-Path $TimeDir)) { New-Item -ItemType Directory -Path $TimeDir | Out-Null }
        
        if (Check-Tool "MFTECmd.exe") {
            .\MFTECmd.exe -f "$env:SystemDrive\$MFT" --csv "$TimeDir\MFT.csv" --csvf MFT_Timeline.csv
            .\MFTECmd.exe -f "$env:SystemDrive\$LogFile" --csv "$TimeDir\LogFile.csv"
            .\MFTECmd.exe -f "$env:SystemDrive\$UsnJrnl`$J" --csv "$TimeDir\UsnJrnl.csv"
        }
        
        fsutil usn readjournal C: csv | ConvertFrom-Csv | Export-Csv -Path "$TimeDir\USN_Journal.csv" -NoTypeInformation
        
        Get-ChildItem "C:\Windows\Prefetch" -Filter *.pf | Select-Object * | Export-Csv -Path "$TimeDir\Prefetch_Files.csv" -NoTypeInformation
        
        reg export "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" "$TimeDir\Shimcache.reg" /y
        
        Safe-CopyItem -Source "C:\Windows\AppCompat\Programs\Amcache.hve" -Destination $TimeDir
        
        Get-WinEvent -ListLog * | ForEach-Object { Get-WinEvent -LogName $_.LogName -MaxEvents 10000 -ErrorAction SilentlyContinue } | Sort-Object TimeCreated | Export-Csv -Path "$TimeDir\All_Events_Timeline.csv" -NoTypeInformation
        
        Write-Log "Timeline Artifacts collected."
    } catch {
        Handle-Error -Message "Failed to collect Timeline" -Exception $_
    }
}

# Function to Collect Browser Artifacts
function Collect-Browser {
    try {
        Write-Log "Collecting Browser Artifacts..."
        $BrowserDir = Join-Path -Path $OutputDir -ChildPath "Browser"
        if (-not (Test-Path $BrowserDir)) { New-Item -ItemType Directory -Path $BrowserDir | Out-Null }
        
        $chromeHistory = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History"
        if (Test-Path $chromeHistory) {
            Safe-CopyItem -Source $chromeHistory -Destination "$BrowserDir\Chrome_History.sqlite"
        }
        
        $firefoxPath = "$env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\places.sqlite"
        Get-ChildItem $firefoxPath -ErrorAction SilentlyContinue | Safe-CopyItem -Destination $BrowserDir
        
        $edgeHistory = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History"
        if (Test-Path $edgeHistory) {
            Safe-CopyItem -Source $edgeHistory -Destination "$BrowserDir\Edge_History.sqlite"
        }
        
        Safe-CopyItem -Source "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cookies" -Destination $BrowserDir
        Safe-CopyItem -Source "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cookies" -Destination $BrowserDir
        
        Safe-CopyItem -Source "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache" -Destination $BrowserDir\Chrome_Cache -Recurse
        Safe-CopyItem -Source "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache" -Destination $BrowserDir\Edge_Cache -Recurse
        
        Write-Log "Browser Artifacts collected."
    } catch {
        Handle-Error -Message "Failed to collect Browser" -Exception $_
    }
}

# Function to Collect USB History
function Collect-USB {
    try {
        Write-Log "Collecting USB Artifacts..."
        $UsbDir = Join-Path -Path $OutputDir -ChildPath "USB"
        if (-not (Test-Path $UsbDir)) { New-Item -ItemType Directory -Path $UsbDir | Out-Null }
        
        reg export "HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR" "$UsbDir\USBSTOR.reg" /y
        reg export "HKLM\SYSTEM\CurrentControlSet\Enum\USB" "$UsbDir\USB.reg" /y
        
        Get-Content "C:\Windows\inf\setupapi.dev.log" | Select-String -Pattern "USB|VID_|PID_" -Context 5 | Out-File -FilePath "$UsbDir\SetupAPI_Log.txt" -Encoding utf8
        
        Get-CimInstance Win32_PnPEntity | Where-Object { $_.PNPClass -eq "USB" } | Select-Object * | Export-Csv -Path "$UsbDir\USB_Devices.csv" -NoTypeInformation
        
        Write-Log "USB Artifacts collected."
    } catch {
        Handle-Error -Message "Failed to collect USB" -Exception $_
    }
}

# Function to Collect Firewall Logs
function Collect-Firewall {
    try {
        Write-Log "Collecting Firewall Logs..."
        $FwDir = Join-Path -Path $OutputDir -ChildPath "Firewall"
        if (-not (Test-Path $FwDir)) { New-Item -ItemType Directory -Path $FwDir | Out-Null }
        
        Get-NetFirewallRule | Select-Object * | Export-Csv -Path "$FwDir\Firewall_Rules.csv" -NoTypeInformation
        
        Safe-CopyItem -Source "C:\Windows\System32\LogFiles\Firewall\*.log" -Destination $FwDir
        
        wevtutil epl "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall" "$FwDir\Firewall.evtx" -ErrorAction SilentlyContinue
        
        Write-Log "Firewall Logs collected."
    } catch {
        Handle-Error -Message "Failed to collect Firewall" -Exception $_
    }
}

# Function for Custom Collections
function Collect-Custom {
    try {
        Write-Log "Collecting Custom Artifacts..."
        $CustomDir = Join-Path -Path $OutputDir -ChildPath "Custom"
        if (-not (Test-Path $CustomDir)) { New-Item -ItemType Directory -Path $CustomDir | Out-Null }
        
        $lolbas = Get-Process | Where-Object { @('certutil', 'installutil', 'msbuild', 'regsvr32', 'cmstp', 'msiexec') -contains $_.Name.ToLower() }
        Safe-ExportCsv -Data $lolbas -Path "$CustomDir\LOLBAS_Processes.csv"
        
        if (Test-Path "baseline_services.csv") {
            $baseline = Import-Csv "baseline_services.csv"
            $current = Get-Service | Select-Object Name, Status, StartType
            Compare-Object $baseline $current -Property Name, Status, StartType | Export-Csv -Path "$CustomDir\Differential_Services.csv" -NoTypeInformation
        }
        
        Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Defender" -ErrorAction SilentlyContinue | Out-File -FilePath "$CustomDir\Defender_Config.txt" -Encoding utf8
        
        Write-Log "Custom Artifacts collected."
    } catch {
        Handle-Error -Message "Failed to collect Custom" -Exception $_
    }
}

# Function to Collect Cloud Artifacts
function Collect-Cloud {
    try {
        Write-Log "Collecting Cloud Artifacts..."
        $CloudDir = Join-Path -Path $OutputDir -ChildPath "Cloud"
        if (-not (Test-Path $CloudDir)) { New-Item -ItemType Directory -Path $CloudDir | Out-Null }
        
        if (Get-Module -ListAvailable -Name AWSPowerShell.NetCore) {
            Get-EC2Instance | Select-Object * | Export-Csv -Path "$CloudDir\AWS_Instances.csv" -NoTypeInformation
            Get-S3Bucket | Select-Object * | Export-Csv -Path "$CloudDir\AWS_S3_Buckets.csv" -NoTypeInformation
        }
        
        if (Get-Module -ListAvailable -Name Az.Accounts) {
            Connect-AzAccount -WarningAction SilentlyContinue
            Get-AzVM | Select-Object * | Export-Csv -Path "$CloudDir\Azure_VMs.csv" -NoTypeInformation
            Get-AzStorageAccount | Select-Object * | Export-Csv -Path "$CloudDir\Azure_Storage.csv" -NoTypeInformation
        }
        
        if (Test-Path "$env:USERPROFILE\.aws\credentials") {
            Get-Content "$env:USERPROFILE\.aws\credentials" | Out-File -FilePath "$CloudDir\AWS_Credentials.txt" -Encoding utf8
        }
        
        try {
            Invoke-WebRequest -Uri "http://169.254.169.254/latest/meta-data/" -UseBasicParsing | Out-File -FilePath "$CloudDir\AWS_IMDS.txt" -Encoding utf8
        } catch {}
        
        try {
            Invoke-WebRequest -Uri "http://169.254.169.254/metadata/instance?api-version=2021-02-01" -Headers @{"Metadata"="true"} -UseBasicParsing | Out-File -FilePath "$CloudDir\Azure_IMDS.txt" -Encoding utf8
        } catch {}
        
        Write-Log "Cloud Artifacts collected."
    } catch {
        Handle-Error -Message "Failed to collect Cloud" -Exception $_
    }
}

# Function to Password Audit
function Collect-PasswordAudit {
    try {
        Write-Log "Collecting Password Audit Info..."
        $PwdDir = Join-Path -Path $OutputDir -ChildPath "PasswordAudit"
        if (-not (Test-Path $PwdDir)) { New-Item -ItemType Directory -Path $PwdDir | Out-Null }
        
        net accounts /domain | Out-File -FilePath "$PwdDir\Password_Policy.txt" -Encoding utf8
        
        Get-LocalUser | Select-Object Name, PasswordLastSet, PasswordExpires, PasswordRequired | Export-Csv -Path "$PwdDir\Local_Users_Passwords.csv" -NoTypeInformation
        
        if ((Get-CimInstance Win32_ComputerSystem).DomainRole -gt 1) {
            Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue | Out-File -FilePath "$PwdDir\Domain_Password_Policy.txt" -Encoding utf8
        }
        
        Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name MaximumPasswordAge -ErrorAction SilentlyContinue | Out-File -FilePath "$PwdDir\Netlogon_Params.txt" -Encoding utf8
        
        Write-Log "Password Audit collected."
    } catch {
        Handle-Error -Message "Failed to collect PasswordAudit" -Exception $_
    }
}

# Function to SMB Analysis
function Collect-SMB {
    try {
        Write-Log "Collecting SMB Artifacts..."
        $SmbDir = Join-Path -Path $OutputDir -ChildPath "SMB"
        if (-not (Test-Path $SmbDir)) { New-Item -ItemType Directory -Path $SmbDir | Out-Null }
        
        Get-SmbSession | Select-Object * | Export-Csv -Path "$SmbDir\SMB_Sessions.csv" -NoTypeInformation
        
        Get-SmbShare | Select-Object * | Export-Csv -Path "$SmbDir\SMB_Shares.csv" -NoTypeInformation
        
        Get-SmbServerConfiguration | Out-File -FilePath "$SmbDir\SMB_Server_Config.txt" -Encoding utf8
        
        Get-SmbConnection | Select-Object * | Export-Csv -Path "$SmbDir\SMB_Connections.csv" -NoTypeInformation
        
        Write-Log "SMB Artifacts collected."
    } catch {
        Handle-Error -Message "Failed to collect SMB" -Exception $_
    }
}

# Function for Event Analysis
function Collect-EventAnalysis {
    try {
        Write-Log "Running Event Log Analysis..."
        $EventDir = Join-Path -Path $OutputDir -ChildPath "EventAnalysis"
        if (-not (Test-Path $EventDir)) { New-Item -ItemType Directory -Path $EventDir | Out-Null }
        
        if (Check-Tool "hayabusa.exe") {
            .\hayabusa.exe csv-timeline -d "C:\Windows\System32\winevt\Logs" -o "$EventDir\Hayabusa_Timeline.csv" --level medium --no-summary
            .\hayabusa.exe json-timeline -d "C:\Windows\System32\winevt\Logs" -o "$EventDir\Hayabusa_JSON.json" --level high
        } else {
            Get-WinEvent -FilterHashtable @{LogName='*'; Level=1,2} -MaxEvents 5000 -ErrorAction SilentlyContinue | Export-Csv -Path "$EventDir\Critical_Events.csv" -NoTypeInformation
        }
        
        Write-Log "Event Analysis collected."
    } catch {
        Handle-Error -Message "Failed to collect EventAnalysis" -Exception $_
    }
}

# Function for Volatility Preparation
function Collect-VolatilityPrep {
    try {
        Write-Log "Preparing Volatility Analysis..."
        $VolDir = Join-Path -Path $OutputDir -ChildPath "Volatility"
        if (-not (Test-Path $VolDir)) { New-Item -ItemType Directory -Path $VolDir | Out-Null }
        
        $memFile = "$OutputDir\Memory\memory.raw"
        if (Test-Path $memFile -and Check-Tool "vol3.py") {
            python vol3.py -f $memFile windows.info > "$VolDir\Windows_Info.txt"
            python vol3.py -f $memFile windows.pslist > "$VolDir\PsList.txt"
            python vol3.py -f $memFile windows.pstree > "$VolDir\PsTree.txt"
            python vol3.py -f $memFile windows.netscan > "$VolDir\NetScan.txt"
            python vol3.py -f $memFile windows.cmdline > "$VolDir\CmdLine.txt"
            python vol3.py -f $memFile windows.dlllist > "$VolDir\DLLList.txt"
        }
        
        Write-Log "Volatility Prep collected."
    } catch {
        Handle-Error -Message "Failed to collect VolatilityPrep" -Exception $_
    }
}

# Function to Generate AI Prompts
function Collect-AI_Prompts {
    try {
        Write-Log "Generating Analysis Prompts..."
        $AiDir = Join-Path -Path $OutputDir -ChildPath "AI_Prompts"
        if (-not (Test-Path $AiDir)) { New-Item -ItemType Directory -Path $AiDir | Out-Null }
        
        "Review these log entries for anomalies: [Insert content from Logs\Suspicious_Events.csv]" | Out-File -FilePath "$AiDir\Log_Review_Prompt.txt" -Encoding utf8
        
        "Interpret this registry key data: [Insert suspicious registry export]" | Out-File -FilePath "$AiDir\Registry_Interpretation_Prompt.txt" -Encoding utf8
        
        "Analyze potential malware behavior from these strings: [Insert strings output]" | Out-File -FilePath "$AiDir\Malware_Behavior_Prompt.txt" -Encoding utf8
        
        "Suggest next steps based on these findings: [Summarize artifacts]" | Out-File -FilePath "$AiDir\Next_Steps_Prompt.txt" -Encoding utf8
        
        Write-Log "Analysis Prompts generated."
    } catch {
        Handle-Error -Message "Failed to collect AI_Prompts" -Exception $_
    }
}

# Function to Generate Response Report
function Collect-Response_Report {
    try {
        Write-Log "Generating Response Report Skeleton..."
        $ReportFile = Join-Path -Path $OutputDir -ChildPath "Response_Report.txt"
        
        @"
Incident Response Report for $HostName
Date: $(Get-Date)
Detection: [Describe initial indicators]
Verification: [Confirm scope]
Containment: [Isolation measures]
Eradication: [Removal steps]
Recovery: [System restoration]
Lessons Learned: [Improvements]
Artifacts Collected: [List directories]
"@ | Out-File -FilePath $ReportFile -Encoding utf8
        
        Get-ChildItem $OutputDir -Directory | Select-Object Name | Out-File -FilePath $ReportFile -Append -Encoding utf8
        
        Write-Log "Response Report skeleton created."
    } catch {
        Handle-Error -Message "Failed to collect Response_Report" -Exception $_
    }
}

# New Function: Collect Registry Artifacts
function Collect-Registry {
    try {
        Write-Log "Collecting Registry Artifacts..."
        $RegDir = Join-Path -Path $OutputDir -ChildPath "Registry"
        if (-not (Test-Path $RegDir)) { New-Item -ItemType Directory -Path $RegDir | Out-Null }
        
        $hivePaths = @("C:\Windows\System32\config\SYSTEM", "C:\Windows\System32\config\SOFTWARE", "C:\Windows\System32\config\SAM", "C:\Windows\System32\config\SECURITY", "C:\Users\*\NTUSER.DAT", "C:\Users\*\AppData\Local\Microsoft\Windows\UsrClass.dat")
        foreach ($hive in $hivePaths) {
            Get-ChildItem $hive -ErrorAction SilentlyContinue | Safe-CopyItem -Destination $RegDir
        }
        
        if (Check-Tool "RegistryExplorer.exe") {
            # Assume tool usage for export, but simulate with reg export
        } else {
            reg export HKLM\SYSTEM "$RegDir\SYSTEM.reg" /y
            reg export HKLM\SOFTWARE "$RegDir\SOFTWARE.reg" /y
            reg export HKLM\SAM "$RegDir\SAM.reg" /y
            reg export HKLM\SECURITY "$RegDir\SECURITY.reg" /y
            reg export HKCU "$RegDir\HKCU.reg" /y
        }
        
        if (Check-Tool "RECmd.exe") {
            .\RECmd.exe -d "C:\Windows\System32\config" --bn "$RegDir\BatchOutput.txt"
        }
        
        if (Check-Tool "RegRipper3.0\rip.exe") {
            .\rip.exe -r "C:\Windows\System32\config\SYSTEM" -a | Out-File -FilePath "$RegDir\RegRipper_System.txt" -Encoding utf8
            .\rip.exe -r "C:\Windows\System32\config\SOFTWARE" -a | Out-File -FilePath "$RegDir\RegRipper_Software.txt" -Encoding utf8
        }
        
        Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run*" | Out-File -FilePath "$RegDir\RunKeys.txt" -Encoding utf8
        
        Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" | Out-File -FilePath "$RegDir\TimeZone.txt" -Encoding utf8
        
        Write-Log "Registry Artifacts collected."
    } catch {
        Handle-Error -Message "Failed to collect Registry" -Exception $_
    }
}

# New Function: Collect File System Artifacts
function Collect-FileSystem {
    try {
        Write-Log "Collecting File System Artifacts..."
        $FsDir = Join-Path -Path $OutputDir -ChildPath "FileSystem"
        if (-not (Test-Path $FsDir)) { New-Item -ItemType Directory -Path $FsDir | Out-Null }
        
        Get-Volume | Select-Object * | Export-Csv -Path "$FsDir\Volumes.csv" -NoTypeInformation
        
        diskpart /s @( 'list disk', 'exit' ) | Out-File -FilePath "$FsDir\DiskPart.txt" -Encoding utf8
        
        if (Check-Tool "MFTECmd.exe") {
            .\MFTECmd.exe --f "$env:SystemDrive\$MFT" --output "$FsDir\MFT_Dump.csv" --bodyfull
        }
        
        Get-ChildItem "C:\windows.old" -Recurse -ErrorAction SilentlyContinue | Select-Object FullName, CreationTime, LastWriteTime | Export-Csv -Path "$FsDir\WindowsOld.csv" -NoTypeInformation
        
        Get-ChildItem "$env:APPDATA\Microsoft\Windows\Libraries" -Recurse -ErrorAction SilentlyContinue | Out-File -FilePath "$FsDir\Libraries.txt" -Encoding utf8
        
        dir /R "C:\Users" | Out-File -FilePath "$FsDir\ADS_List.txt" -Encoding utf8
        
        Write-Log "File System Artifacts collected."
    } catch {
        Handle-Error -Message "Failed to collect FileSystem" -Exception $_
    }
}

# New Function: Collect Volume Shadow Copies
function Collect-VSS {
    try {
        Write-Log "Collecting VSS Artifacts..."
        $VssDir = Join-Path -Path $OutputDir -ChildPath "VSS"
        if (-not (Test-Path $VssDir)) { New-Item -ItemType Directory -Path $VssDir | Out-Null }
        
        vssadmin list shadows | Out-File -FilePath "$VssDir\VSS_List.txt" -Encoding utf8
        
        if (Check-Tool "ShadowExplorer.exe") {
            # Manual tool, note for offline
            "Use ShadowExplorer for extraction offline." | Out-File -FilePath "$VssDir\Note.txt" -Encoding utf8
        }
        
        if (Check-Tool "libvshadow-tools\vshadowinfo.exe") {
            Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' } | ForEach-Object {
                .\vshadowinfo.exe $_.Path | Out-File -FilePath "$VssDir\VSS_Info_$($_.DriveLetter).txt" -Encoding utf8
            }
        }
        
        if (Check-Tool "VSSMount.exe") {
            .\VSSMount.exe /l > "$VssDir\VSS_Mount_List.txt"
        }
        
        # Copy VSS catalogs
        Safe-CopyItem -Source "C:\System Volume Information\*" -Destination $VssDir -Force
        
        Write-Log "VSS Artifacts collected."
    } catch {
        Handle-Error -Message "Failed to collect VSS" -Exception $_
    }
}

# New Function: File Carving
function Collect-Carving {
    try {
        Write-Log "Performing File Carving..."
        $CarveDir = Join-Path -Path $OutputDir -ChildPath "Carving"
        if (-not (Test-Path $CarveDir)) { New-Item -ItemType Directory -Path $CarveDir | Out-Null }
        
        if (Check-Tool "foremost.exe") {
            .\foremost.exe -i "C:\pagefile.sys" -o "$CarveDir\Foremost_Pagefile" -v
        }
        
        if (Check-Tool "photorec_win.exe") {
            # Photorec is GUI, note for manual run
            "Run PhotoRec manually on unallocated space." | Out-File -FilePath "$CarveDir\PhotoRec_Note.txt" -Encoding utf8
        }
        
        if (Check-Tool "tsk_recover.exe") {
            .\tsk_recover.exe -a image.dd "$CarveDir\Recovered_Files"
        }
        
        # Simple PS carving for known headers (limited)
        function SimpleCarve {
            param ($FilePath, $Header, $Footer, $Ext)
            $bytes = [System.IO.File]::ReadAllBytes($FilePath)
            $positions = 0..($bytes.Length - $Header.Length) | Where-Object { $bytes[$_..($_+$Header.Length-1)] -join '' -eq $Header -join '' }
            foreach ($pos in $positions) {
                $end = $bytes.Length
                for ($i = $pos + $Header.Length; $i -lt $bytes.Length - $Footer.Length; $i++) {
                    if ($bytes[$i..($i+$Footer.Length-1)] -join '' -eq $Footer -join '') {
                        $end = $i + $Footer.Length
                        break
                    }
                }
                [System.IO.File]::WriteAllBytes("$CarveDir\carved_$pos.$Ext", $bytes[$pos..$end])
            }
        }
        # Example for JPG
        $jpgHeader = [byte[]](0xFF,0xD8,0xFF)
        $jpgFooter = [byte[]](0xFF,0xD9)
        SimpleCarve -FilePath "C:\unallocated.bin" -Header $jpgHeader -Footer $jpgFooter -Ext "jpg"
        
        Write-Log "File Carving performed."
    } catch {
        Handle-Error -Message "Failed to collect Carving" -Exception $_
    }
}

# New Function: String Searching
function Collect-StringSearch {
    try {
        Write-Log "Performing String Searching..."
        $StrDir = Join-Path -Path $OutputDir -ChildPath "StringSearch"
        if (-not (Test-Path $StrDir)) { New-Item -ItemType Directory -Path $StrDir | Out-Null }
        
        if (Check-Tool "bstrings.exe") {
            .\bstrings.exe -n 8 -t d "C:\pagefile.sys" > "$StrDir\Pagefile_Strings.txt"
            .\bstrings.exe -n 8 -t d "C:\hiberfil.sys" > "$StrDir\Hiberfil_Strings.txt"
        } else {
            Get-Content "C:\pagefile.sys" -Encoding Byte -ReadCount 4096 | ForEach-Object { [Text.Encoding]::ASCII.GetString($_) | Select-String -Pattern ".{8,}" -AllMatches } | Out-File -FilePath "$StrDir\Pagefile_Strings_PS.txt" -Encoding utf8
        }
        
        # Indexed Search Prep
        "Use Autopsy or similar for indexed searching offline." | Out-File -FilePath "$StrDir\Note.txt" -Encoding utf8
        
        # EXIF Metadata
        if (Check-Tool "exiftool.exe") {
            Get-ChildItem "C:\Users\*\Pictures" -Filter *.jpg,*.png -Recurse | ForEach-Object {
                .\exiftool.exe $_.FullName | Out-File -FilePath "$StrDir\EXIF_$($_.Name).txt" -Encoding utf8
            }
        }
        
        Write-Log "String Searching collected."
    } catch {
        Handle-Error -Message "Failed to collect StringSearch" -Exception $_
    }
}

# New Function: Disk Encryption Check
function Collect-DiskEncryption {
    try {
        Write-Log "Checking Disk Encryption..."
        $EncDir = Join-Path -Path $OutputDir -ChildPath "DiskEncryption"
        if (-not (Test-Path $EncDir)) { New-Item -ItemType Directory -Path $EncDir | Out-Null }
        
        manage-bde -status | Out-File -FilePath "$EncDir\BitLocker_Status.txt" -Encoding utf8
        
        if (Check-Tool "EDD.exe") {
            .\EDD.exe C: | Out-File -FilePath "$EncDir\EDD_Report.txt" -Encoding utf8
        }
        
        Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\TPM" -ErrorAction SilentlyContinue | Out-File -FilePath "$EncDir\TPM_Status.txt" -Encoding utf8
        
        Write-Log "Disk Encryption info collected."
    } catch {
        Handle-Error -Message "Failed to collect DiskEncryption" -Exception $_
    }
}

# New Function: User Profiling
function Collect-UserProfiling {
    try {
        Write-Log "Profiling Users..."
        $UserDir = Join-Path -Path $OutputDir -ChildPath "UserProfiling"
        if (-not (Test-Path $UserDir)) { New-Item -ItemType Directory -Path $UserDir | Out-Null }
        
        reg export "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" "$UserDir\ProfileList.reg" /y
        
        Get-ChildItem "C:\Users" -Directory | ForEach-Object {
            $user = $_.Name
            Get-ItemProperty "C:\Users\$user\NTUSER.DAT" -ErrorAction SilentlyContinue | Out-File -FilePath "$UserDir\$user_NTUSER.txt" -Encoding utf8
        }
        
        # RID from SAM
        if (Check-Tool "RegistryExplorer.exe") {
            "Load SAM hive in RegistryExplorer for RID profiling." | Out-File -FilePath "$UserDir\Note.txt" -Encoding utf8
        }
        
        Get-LocalUser | Select-Object * | Export-Csv -Path "$UserDir\Local_Users.csv" -NoTypeInformation
        
        Write-Log "User Profiling collected."
    } catch {
        Handle-Error -Message "Failed to collect UserProfiling" -Exception $_
    }
}

# New Function: Network History
function Collect-NetworkHistory {
    try {
        Write-Log "Collecting Network History..."
        $NetHistDir = Join-Path -Path $OutputDir -ChildPath "NetworkHistory"
        if (-not (Test-Path $NetHistDir)) { New-Item -ItemType Directory -Path $NetHistDir | Out-Null }
        
        reg export "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList" "$NetHistDir\NetworkList.reg" /y
        
        Get-NetAdapterBinding | Export-Csv -Path "$NetHistDir\Adapter_Bindings.csv" -NoTypeInformation
        
        # Geolocation from WiFi
        if (Check-Tool "wigle-cli.exe") {
            Get-Content "$NetHistDir\WiFi_BSSIDs.txt" | ForEach-Object { .\wigle-cli.exe -b $_ } | Out-File -FilePath "$NetHistDir\WiFi_Geo.txt" -Encoding utf8
        }
        
        Write-Log "Network History collected."
    } catch {
        Handle-Error -Message "Failed to collect NetworkHistory" -Exception $_
    }
}

# New Function: Installed Apps
function Collect-InstalledApps {
    try {
        Write-Log "Collecting Installed Apps..."
        $AppDir = Join-Path -Path $OutputDir -ChildPath "InstalledApps"
        if (-not (Test-Path $AppDir)) { New-Item -ItemType Directory -Path $AppDir | Out-Null }
        
        reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" "$AppDir\Uninstall.reg" /y
        reg export "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" "$AppDir\Uninstall_HKCU.reg" /y
        
        Get-AppxPackage | Select-Object * | Export-Csv -Path "$AppDir\Windows_Apps.csv" -NoTypeInformation
        
        Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore" -Recurse -ErrorAction SilentlyContinue | Out-File -FilePath "$AppDir\Capability_Access.txt" -Encoding utf8
        
        Write-Log "Installed Apps collected."
    } catch {
        Handle-Error -Message "Failed to collect InstalledApps" -Exception $_
    }
}

# New Function: Autostart Locations
function Collect-Autostart {
    try {
        Write-Log "Collecting Autostart Locations..."
        $AutoDir = Join-Path -Path $OutputDir -ChildPath "Autostart"
        if (-not (Test-Path $AutoDir)) { New-Item -ItemType Directory -Path $AutoDir | Out-Null }
        
        Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" | Out-File -FilePath "$AutoDir\Run.txt" -Encoding utf8
        Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" | Out-File -FilePath "$AutoDir\Run.txt" -Append -Encoding utf8
        
        Get-CimInstance Win32_StartupCommand | Export-Csv -Path "$AutoDir\Startup_Commands.csv" -NoTypeInformation
        
        Write-Log "Autostart Locations collected."
    } catch {
        Handle-Error -Message "Failed to collect Autostart" -Exception $_
    }
}

# Main Execution
foreach ($module in $SelectedModules) {
    $module = $module.Trim()
    try {
        Invoke-Expression "Collect-$module"
    } catch {
        Handle-Error -Message "Failed to execute module $module" -Exception $_
    }
}

# Summary and Compression
$SummaryFile = Join-Path -Path $OutputDir -ChildPath "Summary.txt"
@"
Collection Summary
Host: $HostName
Date: $(Get-Date)
Version: $ScriptVersion
Modules: $($SelectedModules -join ', ')
Review subdirectories for artifacts.
"@ | Out-File -FilePath $SummaryFile -Encoding utf8

if (Get-Command Compress-Archive) {
    Compress-Archive -Path "$OutputDir\*" -DestinationPath "$OutputDir.zip" -CompressionLevel Optimal -Force
    Write-Log "Output archived to $OutputDir.zip"
}

Write-Log "Script completed."
Write-Host "Collection finished. Results in $OutputDir"
