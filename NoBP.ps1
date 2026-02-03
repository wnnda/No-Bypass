# NoBP - Advanced Cheat Detection Suite
# Created by Wanda
# Version 1.0

param(
    [string]$TargetProcess = "javaw"
)

# Global variables
$Global:LogDirectory = ".\Wanda SS"
$Global:MonitoringActive = $false
$Global:DLLSnapshot = @{}
$Global:DLLHistory = @{}

# Create log directory
if (-not (Test-Path $Global:LogDirectory)) {
    New-Item -ItemType Directory -Path $Global:LogDirectory | Out-Null
}

# Add Windows API types
Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public class WinAPI {
    [DllImport("user32.dll")]
    public static extern short GetAsyncKeyState(int vKey);
    
    [DllImport("user32.dll")]
    public static extern IntPtr GetForegroundWindow();
    
    [DllImport("user32.dll")]
    public static extern IntPtr GetWindow(IntPtr hWnd, uint uCmd);
    
    [DllImport("user32.dll")]
    public static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);
    
    [DllImport("user32.dll")]
    public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);
    
    [DllImport("user32.dll")]
    public static extern bool IsWindowVisible(IntPtr hWnd);
    
    [DllImport("user32.dll")]
    public static extern int GetWindowLong(IntPtr hWnd, int nIndex);
    
    public const int GWL_EXSTYLE = -20;
    public const int WS_EX_LAYERED = 0x80000;
    public const int WS_EX_TRANSPARENT = 0x20;
    public const int WS_EX_TOPMOST = 0x8;
    public const uint GW_HWNDNEXT = 2;
    public const int VK_F9 = 0x78;
}
"@

function Show-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "  ███╗   ██╗ ██████╗ ██████╗ ██████╗ " -ForegroundColor Cyan
    Write-Host "  ████╗  ██║██╔═══██╗██╔══██╗██╔══██╗" -ForegroundColor Cyan
    Write-Host "  ██╔██╗ ██║██║   ██║██████╔╝██████╔╝" -ForegroundColor Cyan
    Write-Host "  ██║╚██╗██║██║   ██║██╔══██╗██╔═══╝ " -ForegroundColor Cyan
    Write-Host "  ██║ ╚████║╚██████╔╝██████╔╝██║     " -ForegroundColor Cyan
    Write-Host "  ╚═╝  ╚═══╝ ╚═════╝ ╚═════╝ ╚═╝     " -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Advanced Cheat Detection Suite" -ForegroundColor White
    Write-Host "  Created by Wanda" -ForegroundColor DarkCyan
    Write-Host "  ════════════════════════════════════════" -ForegroundColor DarkGray
    Write-Host ""
}

function Show-Menu {
    Show-Banner
    Write-Host "  [1] String Pattern Detection" -ForegroundColor Yellow
    Write-Host "  [2] DLL Unload Monitor" -ForegroundColor Yellow
    Write-Host "  [3] Active DLL Injection Scan" -ForegroundColor Yellow
    Write-Host "  [4] GUI Overlay & Hook Detection" -ForegroundColor Yellow
    Write-Host "  [5] Real-Time Injection Monitor" -ForegroundColor Yellow
    Write-Host "  [6] Complete System Scan" -ForegroundColor Yellow
    Write-Host "  [7] Driver Analysis" -ForegroundColor Yellow
    Write-Host "  [8] Forensic File Search" -ForegroundColor Yellow
    Write-Host "  [9] View Scan History" -ForegroundColor Yellow
    Write-Host "  [0] Exit" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Target Process: " -NoNewline -ForegroundColor Gray
    Write-Host $Global:TargetProcess -ForegroundColor White
    Write-Host ""
    Write-Host "  ════════════════════════════════════════" -ForegroundColor DarkGray
    Write-Host ""
}

function Write-ScanLog {
    param(
        [string]$Message,
        [string]$Level = "INFO",
        [string]$LogFile
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $entry = "[$timestamp] [$Level] $Message"
    
    if ($LogFile) {
        Add-Content -Path $LogFile -Value $entry
    }
    
    switch ($Level) {
        "CRITICAL" { 
            Write-Host "  [!] " -NoNewline -ForegroundColor Magenta
            Write-Host $Message -ForegroundColor White
            [Console]::Beep(2000, 300)
        }
        "ALERT" { 
            Write-Host "  [!] " -NoNewline -ForegroundColor Red
            Write-Host $Message -ForegroundColor White
        }
        "WARN" { 
            Write-Host "  [*] " -NoNewline -ForegroundColor Yellow
            Write-Host $Message -ForegroundColor White
        }
        "SUCCESS" {
            Write-Host "  [+] " -NoNewline -ForegroundColor Green
            Write-Host $Message -ForegroundColor White
        }
        default { 
            Write-Host "  [-] " -NoNewline -ForegroundColor Cyan
            Write-Host $Message -ForegroundColor White
        }
    }
}

function Wait-ForKeyPress {
    Write-Host ""
    Write-Host "  ════════════════════════════════════════" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Get-TargetProcess {
    $process = Get-Process -Name $Global:TargetProcess -ErrorAction SilentlyContinue | Select-Object -First 1
    return $process
}

# ═══════════════════════════════════════════════════════════
# SCAN 1: STRING PATTERN DETECTION
# ═══════════════════════════════════════════════════════════
function Start-StringPatternScan {
    Show-Banner
    Write-Host "  STRING PATTERN DETECTION" -ForegroundColor Cyan
    Write-Host "  ════════════════════════════════════════" -ForegroundColor DarkGray
    Write-Host ""
    
    $logFile = Join-Path $Global:LogDirectory "String_Detection_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    
    $process = Get-TargetProcess
    if (-not $process) {
        Write-ScanLog "Process '$Global:TargetProcess' not found!" "ALERT" $logFile
        Wait-ForKeyPress
        return
    }
    
    Write-ScanLog "Scanning process: $($process.ProcessName) (PID: $($process.Id))" "INFO" $logFile
    Write-ScanLog "Starting string pattern analysis..." "INFO" $logFile
    Write-Host ""
    
    # Cheat signature patterns
    $cheatSignatures = @(
        'aimbot', 'wallhack', 'esp', 'triggerbot', 'autoclicker',
        'anchor', 'crystal', 'killaura', 'velocity', 'scaffold',
        'imgui', 'dear imgui', 'cheat menu', 'inject', 'unload',
        'bypass', 'noclip', 'fly', 'speed', 'reach', 'bhop',
        'automine', 'xray', 'tracers', 'freecam', 'fastbreak'
    )
    
    $detectionCount = 0
    $scannedModules = 0
    
    foreach ($module in $process.Modules) {
        $scannedModules++
        $moduleName = $module.ModuleName.ToLower()
        $modulePath = $module.FileName.ToLower()
        
        foreach ($signature in $cheatSignatures) {
            if ($moduleName -like "*$signature*" -or $modulePath -like "*$signature*") {
                $detectionCount++
                Write-ScanLog "CHEAT SIGNATURE DETECTED!" "CRITICAL" $logFile
                Write-ScanLog "  Signature: $signature" "ALERT" $logFile
                Write-ScanLog "  Module: $($module.ModuleName)" "ALERT" $logFile
                Write-ScanLog "  Path: $($module.FileName)" "ALERT" $logFile
                Write-ScanLog "  Size: $($module.Size) bytes" "INFO" $logFile
                Write-Host ""
                
                # Check signature
                try {
                    $sig = Get-AuthenticodeSignature $module.FileName
                    if ($sig.Status -ne 'Valid') {
                        Write-ScanLog "  File is UNSIGNED/INVALID!" "CRITICAL" $logFile
                    }
                } catch { }
                
                break
            }
        }
    }
    
    Write-Host ""
    Write-ScanLog "Scan completed!" "SUCCESS" $logFile
    Write-ScanLog "Modules scanned: $scannedModules" "INFO" $logFile
    Write-ScanLog "Detections found: $detectionCount" "INFO" $logFile
    
    if ($detectionCount -eq 0) {
        Write-ScanLog "No cheat signatures detected in module names" "SUCCESS" $logFile
    }
    
    Write-ScanLog "Results saved to: $logFile" "INFO" $logFile
    
    Wait-ForKeyPress
}

# ═══════════════════════════════════════════════════════════
# SCAN 2: DLL UNLOAD MONITOR
# ═══════════════════════════════════════════════════════════
function Start-DLLUnloadMonitor {
    Show-Banner
    Write-Host "  DLL UNLOAD MONITOR" -ForegroundColor Cyan
    Write-Host "  ════════════════════════════════════════" -ForegroundColor DarkGray
    Write-Host ""
    
    $logFile = Join-Path $Global:LogDirectory "DLL_Unload_Monitor_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    
    Write-ScanLog "Starting real-time DLL unload monitoring..." "INFO" $logFile
    Write-ScanLog "Monitoring interval: 100ms" "INFO" $logFile
    Write-ScanLog "Press Ctrl+C to stop monitoring" "WARN" $logFile
    Write-Host ""
    
    $previousSnapshot = @{}
    $dllHistory = @{}
    $scanCount = 0
    $unloadCount = 0
    
    try {
        while ($true) {
            $scanCount++
            $process = Get-TargetProcess
            
            if ($process) {
                # Take current snapshot
                $currentSnapshot = @{}
                $process.Modules | ForEach-Object {
                    $currentSnapshot[$_.ModuleName] = @{
                        Path = $_.FileName
                        Size = $_.Size
                        Base = $_.BaseAddress.ToString()
                    }
                }
                
                # Check for newly loaded DLLs
                foreach ($dll in $currentSnapshot.Keys) {
                    if (-not $previousSnapshot.ContainsKey($dll)) {
                        Write-ScanLog "DLL LOADED: $dll" "SUCCESS" $logFile
                        Write-ScanLog "  Path: $($currentSnapshot[$dll].Path)" "INFO" $logFile
                        
                        if (-not $dllHistory.ContainsKey($dll)) {
                            $dllHistory[$dll] = @{
                                LoadCount = 1
                                UnloadCount = 0
                                LastLoad = Get-Date
                            }
                        } else {
                            $dllHistory[$dll].LoadCount++
                            $dllHistory[$dll].LastLoad = Get-Date
                        }
                    }
                }
                
                # Check for unloaded DLLs
                foreach ($dll in $previousSnapshot.Keys) {
                    if (-not $currentSnapshot.ContainsKey($dll)) {
                        $unloadCount++
                        Write-Host ""
                        Write-ScanLog "DLL UNLOADED DETECTED!" "CRITICAL" $logFile
                        Write-ScanLog "  DLL Name: $dll" "ALERT" $logFile
                        Write-ScanLog "  Previous Path: $($previousSnapshot[$dll].Path)" "ALERT" $logFile
                        
                        if ($dllHistory.ContainsKey($dll)) {
                            $dllHistory[$dll].UnloadCount++
                            $duration = ((Get-Date) - $dllHistory[$dll].LastLoad).TotalSeconds
                            Write-ScanLog "  Load duration: $([math]::Round($duration, 2)) seconds" "INFO" $logFile
                            
                            if ($dllHistory[$dll].UnloadCount -ge 2) {
                                Write-ScanLog "  REPEATED UNLOAD! Count: $($dllHistory[$dll].UnloadCount)" "CRITICAL" $logFile
                                Write-ScanLog "  This is highly suspicious behavior!" "CRITICAL" $logFile
                            }
                        }
                        Write-Host ""
                    }
                }
                
                $previousSnapshot = $currentSnapshot
                
                # Status update every 100 scans
                if ($scanCount % 100 -eq 0) {
                    Write-Host "  [~] Monitoring... (Scans: $scanCount | Unloads detected: $unloadCount)" -ForegroundColor DarkGray
                }
            } else {
                if ($previousSnapshot.Count -gt 0) {
                    Write-ScanLog "Process terminated" "WARN" $logFile
                    $previousSnapshot = @{}
                }
            }
            
            Start-Sleep -Milliseconds 100
        }
    } catch {
        if ($_.Exception.Message -notlike "*terminated by the user*") {
            Write-ScanLog "Error: $_" "ALERT" $logFile
        }
    }
    
    Write-Host ""
    Write-ScanLog "Monitoring stopped" "INFO" $logFile
    Write-ScanLog "Total scans: $scanCount" "INFO" $logFile
    Write-ScanLog "Unloads detected: $unloadCount" "INFO" $logFile
    Write-ScanLog "Results saved to: $logFile" "INFO" $logFile
    
    Wait-ForKeyPress
}

# ═══════════════════════════════════════════════════════════
# SCAN 3: ACTIVE DLL INJECTION SCAN
# ═══════════════════════════════════════════════════════════
function Start-ActiveDLLScan {
    Show-Banner
    Write-Host "  ACTIVE DLL INJECTION SCAN" -ForegroundColor Cyan
    Write-Host "  ════════════════════════════════════════" -ForegroundColor DarkGray
    Write-Host ""
    
    $logFile = Join-Path $Global:LogDirectory "Active_DLL_Scan_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    
    $process = Get-TargetProcess
    if (-not $process) {
        Write-ScanLog "Process '$Global:TargetProcess' not found!" "ALERT" $logFile
        Wait-ForKeyPress
        return
    }
    
    Write-ScanLog "Scanning process: $($process.ProcessName) (PID: $($process.Id))" "INFO" $logFile
    Write-ScanLog "Analyzing loaded DLL modules..." "INFO" $logFile
    Write-Host ""
    
    $legitimatePaths = @(
        'C:\Windows\System32',
        'C:\Windows\SysWOW64',
        'C:\Program Files\Java',
        'C:\Program Files (x86)\Java',
        'C:\Program Files\Minecraft',
        'C:\Program Files (x86)\Minecraft',
        'C:\Program Files\WindowsApps'
    )
    
    $suspiciousCount = 0
    $totalModules = 0
    
    foreach ($module in $process.Modules) {
        $totalModules++
        $modulePath = $module.FileName
        $isLegitimate = $false
        
        foreach ($path in $legitimatePaths) {
            if ($modulePath -like "$path*") {
                $isLegitimate = $true
                break
            }
        }
        
        if (-not $isLegitimate) {
            $suspiciousCount++
            Write-ScanLog "SUSPICIOUS DLL DETECTED!" "ALERT" $logFile
            Write-ScanLog "  Module: $($module.ModuleName)" "WARN" $logFile
            Write-ScanLog "  Path: $modulePath" "WARN" $logFile
            Write-ScanLog "  Size: $($module.Size) bytes" "INFO" $logFile
            Write-ScanLog "  Base Address: $($module.BaseAddress)" "INFO" $logFile
            
            # Check digital signature
            try {
                $signature = Get-AuthenticodeSignature $modulePath
                if ($signature.Status -eq 'Valid') {
                    Write-ScanLog "  Signature: Valid ($($signature.SignerCertificate.Subject))" "SUCCESS" $logFile
                } else {
                    Write-ScanLog "  Signature: INVALID/UNSIGNED" "CRITICAL" $logFile
                }
            } catch {
                Write-ScanLog "  Signature: Could not verify" "WARN" $logFile
            }
            
            Write-Host ""
        }
    }
    
    Write-Host ""
    Write-ScanLog "Scan completed!" "SUCCESS" $logFile
    Write-ScanLog "Total modules: $totalModules" "INFO" $logFile
    Write-ScanLog "Suspicious modules: $suspiciousCount" "INFO" $logFile
    
    if ($suspiciousCount -eq 0) {
        Write-ScanLog "No suspicious DLL injections detected" "SUCCESS" $logFile
    }
    
    Write-ScanLog "Results saved to: $logFile" "INFO" $logFile
    
    Wait-ForKeyPress
}

# ═══════════════════════════════════════════════════════════
# SCAN 4: GUI OVERLAY & HOOK DETECTION
# ═══════════════════════════════════════════════════════════
function Start-GUIHookDetection {
    Show-Banner
    Write-Host "  GUI OVERLAY & HOOK DETECTION" -ForegroundColor Cyan
    Write-Host "  ════════════════════════════════════════" -ForegroundColor DarkGray
    Write-Host ""
    
    $logFile = Join-Path $Global:LogDirectory "GUI_Hook_Detection_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    
    $process = Get-TargetProcess
    if (-not $process) {
        Write-ScanLog "Process '$Global:TargetProcess' not found!" "ALERT" $logFile
        Wait-ForKeyPress
        return
    }
    
    Write-ScanLog "Scanning for GUI overlays and graphics hooks..." "INFO" $logFile
    Write-ScanLog "Target: $($process.ProcessName) (PID: $($process.Id))" "INFO" $logFile
    Write-Host ""
    
    # Part 1: Check for overlay-related DLLs
    Write-ScanLog "Checking for graphics API hooks..." "INFO" $logFile
    
    $overlayIndicators = @(
        'imgui', 'dear', 'overlay', 'd3d9', 'd3d11', 'd3d12',
        'dxgi', 'opengl32', 'vulkan', 'menu', 'gui'
    )
    
    $detectionCount = 0
    
    foreach ($module in $process.Modules) {
        $moduleName = $module.ModuleName.ToLower()
        $modulePath = $module.FileName.ToLower()
        
        foreach ($indicator in $overlayIndicators) {
            if (($moduleName -like "*$indicator*" -or $modulePath -like "*$indicator*") -and
                $modulePath -notlike "*\windows\*" -and 
                $modulePath -notlike "*\program files\*") {
                
                $detectionCount++
                Write-ScanLog "OVERLAY DLL DETECTED!" "CRITICAL" $logFile
                Write-ScanLog "  Module: $($module.ModuleName)" "ALERT" $logFile
                Write-ScanLog "  Path: $($module.FileName)" "ALERT" $logFile
                Write-ScanLog "  Matches pattern: $indicator" "WARN" $logFile
                Write-Host ""
                break
            }
        }
    }
    
    # Part 2: Check for overlay windows
    Write-Host ""
    Write-ScanLog "Checking for overlay windows..." "INFO" $logFile
    
    $gameWindow = $process.MainWindowHandle
    if ($gameWindow -ne 0) {
        $currentWindow = $gameWindow
        $overlayCount = 0
        
        while ($currentWindow -ne [IntPtr]::Zero) {
            $currentWindow = [WinAPI]::GetWindow($currentWindow, [WinAPI]::GW_HWNDNEXT)
            
            if ($currentWindow -ne [IntPtr]::Zero) {
                $isVisible = [WinAPI]::IsWindowVisible($currentWindow)
                
                if ($isVisible) {
                    $exStyle = [WinAPI]::GetWindowLong($currentWindow, [WinAPI]::GWL_EXSTYLE)
                    
                    $isLayered = ($exStyle -band [WinAPI]::WS_EX_LAYERED) -ne 0
                    $isTransparent = ($exStyle -band [WinAPI]::WS_EX_TRANSPARENT) -ne 0
                    $isTopmost = ($exStyle -band [WinAPI]::WS_EX_TOPMOST) -ne 0
                    
                    if ($isLayered -and ($isTransparent -or $isTopmost)) {
                        $processId = 0
                        [WinAPI]::GetWindowThreadProcessId($currentWindow, [ref]$processId) | Out-Null
                        
                        $owningProcess = Get-Process -Id $processId -ErrorAction SilentlyContinue
                        
                        if ($processId -eq $process.Id) {
                            $overlayCount++
                            $detectionCount++
                            Write-ScanLog "OVERLAY WINDOW DETECTED!" "CRITICAL" $logFile
                            Write-ScanLog "  Owned by game process!" "CRITICAL" $logFile
                            Write-ScanLog "  Layered: $isLayered | Transparent: $isTransparent | Topmost: $isTopmost" "WARN" $logFile
                            Write-Host ""
                        }
                    }
                }
            }
        }
    }
    
    Write-Host ""
    Write-ScanLog "Scan completed!" "SUCCESS" $logFile
    Write-ScanLog "Total detections: $detectionCount" "INFO" $logFile
    
    if ($detectionCount -eq 0) {
        Write-ScanLog "No GUI overlays or hooks detected" "SUCCESS" $logFile
    }
    
    Write-ScanLog "Results saved to: $logFile" "INFO" $logFile
    
    Wait-ForKeyPress
}

# ═══════════════════════════════════════════════════════════
# SCAN 5: REAL-TIME INJECTION MONITOR
# ═══════════════════════════════════════════════════════════
function Start-RealTimeMonitor {
    Show-Banner
    Write-Host "  REAL-TIME INJECTION MONITOR" -ForegroundColor Cyan
    Write-Host "  ════════════════════════════════════════" -ForegroundColor DarkGray
    Write-Host ""
    
    $logFile = Join-Path $Global:LogDirectory "RealTime_Monitor_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    
    Write-ScanLog "Starting real-time injection monitoring..." "INFO" $logFile
    Write-ScanLog "Detection interval: 50ms (ultra-fast)" "INFO" $logFile
    Write-ScanLog "Press Ctrl+C to stop monitoring" "WARN" $logFile
    Write-Host ""
    
    $previousSnapshot = @{}
    $scanCount = 0
    $injectionCount = 0
    
    try {
        while ($true) {
            $scanCount++
            $process = Get-TargetProcess
            
            if ($process) {
                $currentSnapshot = @{}
                $process.Modules | ForEach-Object {
                    $currentSnapshot[$_.ModuleName] = @{
                        Path = $_.FileName
                        Size = $_.Size
                    }
                }
                
                # Detect new injections
                foreach ($dll in $currentSnapshot.Keys) {
                    if (-not $previousSnapshot.ContainsKey($dll)) {
                        $injectionCount++
                        Write-Host ""
                        Write-ScanLog "NEW INJECTION DETECTED!" "CRITICAL" $logFile
                        Write-ScanLog "  DLL: $dll" "ALERT" $logFile
                        Write-ScanLog "  Path: $($currentSnapshot[$dll].Path)" "ALERT" $logFile
                        Write-ScanLog "  Size: $($currentSnapshot[$dll].Size) bytes" "INFO" $logFile
                        
                        # Quick signature check
                        try {
                            $sig = Get-AuthenticodeSignature $currentSnapshot[$dll].Path
                            if ($sig.Status -ne 'Valid') {
                                Write-ScanLog "  WARNING: UNSIGNED DLL!" "CRITICAL" $logFile
                            }
                        } catch { }
                        
                        Write-Host ""
                    }
                }
                
                $previousSnapshot = $currentSnapshot
                
                if ($scanCount % 200 -eq 0) {
                    Write-Host "  [~] Monitoring... (Scans: $scanCount | Injections: $injectionCount)" -ForegroundColor DarkGray
                }
            } else {
                if ($previousSnapshot.Count -gt 0) {
                    Write-ScanLog "Process terminated" "WARN" $logFile
                    $previousSnapshot = @{}
                }
            }
            
            Start-Sleep -Milliseconds 50
        }
    } catch {
        if ($_.Exception.Message -notlike "*terminated by the user*") {
            Write-ScanLog "Error: $_" "ALERT" $logFile
        }
    }
    
    Write-Host ""
    Write-ScanLog "Monitoring stopped" "INFO" $logFile
    Write-ScanLog "Total scans: $scanCount" "INFO" $logFile
    Write-ScanLog "Injections detected: $injectionCount" "INFO" $logFile
    Write-ScanLog "Results saved to: $logFile" "INFO" $logFile
    
    Wait-ForKeyPress
}

# ═══════════════════════════════════════════════════════════
# SCAN 6: COMPLETE SYSTEM SCAN
# ═══════════════════════════════════════════════════════════
function Start-CompleteSystemScan {
    Show-Banner
    Write-Host "  COMPLETE SYSTEM SCAN" -ForegroundColor Cyan
    Write-Host "  ════════════════════════════════════════" -ForegroundColor DarkGray
    Write-Host ""
    
    $logFile = Join-Path $Global:LogDirectory "Complete_Scan_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    
    $process = Get-TargetProcess
    if (-not $process) {
        Write-ScanLog "Process '$Global:TargetProcess' not found!" "ALERT" $logFile
        Wait-ForKeyPress
        return
    }
    
    Write-ScanLog "Starting comprehensive scan..." "INFO" $logFile
    Write-ScanLog "Target: $($process.ProcessName) (PID: $($process.Id))" "INFO" $logFile
    Write-Host ""
    
    $totalDetections = 0
    
    # Scan 1: String patterns
    Write-ScanLog "[1/4] Scanning for cheat signatures..." "INFO" $logFile
    $cheatSignatures = @('aimbot', 'wallhack', 'esp', 'inject', 'imgui', 'anchor', 'crystal')
    foreach ($module in $process.Modules) {
        $name = $module.ModuleName.ToLower()
        $path = $module.FileName.ToLower()
        foreach ($sig in $cheatSignatures) {
            if ($name -like "*$sig*" -or $path -like "*$sig*") {
                $totalDetections++
                Write-ScanLog "  Signature detected: $sig in $($module.ModuleName)" "ALERT" $logFile
            }
        }
    }
    
    # Scan 2: Suspicious DLLs
    Write-Host ""
    Write-ScanLog "[2/4] Checking for suspicious DLLs..." "INFO" $logFile
    $legitimatePaths = @('C:\Windows', 'C:\Program Files')
    foreach ($module in $process.Modules) {
        $isLegit = $false
        foreach ($path in $legitimatePaths) {
            if ($module.FileName -like "$path*") { $isLegit = $true; break }
        }
        if (-not $isLegit) {
            $totalDetections++
            Write-ScanLog "  Suspicious DLL: $($module.ModuleName)" "ALERT" $logFile
        }
    }
    
    # Scan 3: Graphics hooks
    Write-Host ""
    Write-ScanLog "[3/4] Checking for graphics hooks..." "INFO" $logFile
    $overlayIndicators = @('imgui', 'overlay', 'd3d')
    foreach ($module in $process.Modules) {
        foreach ($indicator in $overlayIndicators) {
            if ($module.ModuleName.ToLower() -like "*$indicator*" -and 
                $module.FileName -notlike "*\Windows\*") {
                $totalDetections++
                Write-ScanLog "  Graphics hook detected: $($module.ModuleName)" "ALERT" $logFile
            }
        }
    }
    
    # Scan 4: Unsigned modules
    Write-Host ""
    Write-ScanLog "[4/4] Verifying signatures..." "INFO" $logFile
    foreach ($module in $process.Modules) {
        try {
            $sig = Get-AuthenticodeSignature $module.FileName
            if ($sig.Status -ne 'Valid') {
                $totalDetections++
                Write-ScanLog "  Unsigned DLL: $($module.ModuleName)" "WARN" $logFile
            }
        } catch { }
    }
    
    Write-Host ""
    Write-ScanLog "Scan completed!" "SUCCESS" $logFile
    Write-ScanLog "Total detections: $totalDetections" "INFO" $logFile
    
    if ($totalDetections -eq 0) {
        Write-ScanLog "System appears clean" "SUCCESS" $logFile
    } else {
        Write-ScanLog "Multiple issues detected - investigate further!" "CRITICAL" $logFile
    }
    
    Write-ScanLog "Results saved to: $logFile" "INFO" $logFile
    
    Wait-ForKeyPress
}

# ═══════════════════════════════════════════════════════════
# SCAN 7: DRIVER ANALYSIS
# ═══════════════════════════════════════════════════════════
function Start-DriverAnalysis {
    Show-Banner
    Write-Host "  DRIVER ANALYSIS" -ForegroundColor Cyan
    Write-Host "  ════════════════════════════════════════" -ForegroundColor DarkGray
    Write-Host ""
    
    $logFile = Join-Path $Global:LogDirectory "Driver_Analysis_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    
    Write-ScanLog "Analyzing loaded kernel drivers..." "INFO" $logFile
    Write-Host ""
    
    $drivers = Get-WmiObject Win32_SystemDriver | Where-Object { $_.State -eq 'Running' }
    $suspiciousCount = 0
    
    foreach ($driver in $drivers) {
        $driverPath = $driver.PathName
        
        # Check signature
        if (Test-Path $driverPath) {
            $sig = Get-AuthenticodeSignature $driverPath
            
            if ($sig.Status -ne 'Valid') {
                $suspiciousCount++
                Write-ScanLog "UNSIGNED DRIVER DETECTED!" "CRITICAL" $logFile
                Write-ScanLog "  Name: $($driver.Name)" "ALERT" $logFile
                Write-ScanLog "  Path: $driverPath" "ALERT" $logFile
                Write-ScanLog "  State: $($driver.State)" "WARN" $logFile
                Write-Host ""
            }
        }
        
        # Check for suspicious locations
        if ($driverPath -notlike "*\Windows\*" -and $driverPath -notlike "*\Program Files\*") {
            $suspiciousCount++
            Write-ScanLog "DRIVER IN UNUSUAL LOCATION!" "WARN" $logFile
            Write-ScanLog "  Name: $($driver.Name)" "WARN" $logFile
            Write-ScanLog "  Path: $driverPath" "WARN" $logFile
            Write-Host ""
        }
    }
    
    Write-ScanLog "Driver analysis completed!" "SUCCESS" $logFile
    Write-ScanLog "Total drivers: $($drivers.Count)" "INFO" $logFile
    Write-ScanLog "Suspicious drivers: $suspiciousCount" "INFO" $logFile
    
    if ($suspiciousCount -eq 0) {
        Write-ScanLog "No suspicious drivers detected" "SUCCESS" $logFile
    }
    
    Write-ScanLog "Results saved to: $logFile" "INFO" $logFile
    
    Wait-ForKeyPress
}

# ═══════════════════════════════════════════════════════════
# SCAN 8: FORENSIC FILE SEARCH
# ═══════════════════════════════════════════════════════════
function Start-ForensicFileSearch {
    Show-Banner
    Write-Host "  FORENSIC FILE SEARCH" -ForegroundColor Cyan
    Write-Host "  ════════════════════════════════════════" -ForegroundColor DarkGray
    Write-Host ""
    
    $logFile = Join-Path $Global:LogDirectory "Forensic_Search_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    
    Write-ScanLog "Searching for cheat-related files..." "INFO" $logFile
    Write-ScanLog "This may take a few minutes..." "WARN" $logFile
    Write-Host ""
    
    $searchPaths = @(
        "$env:USERPROFILE\Downloads",
        "$env:USERPROFILE\Desktop",
        "$env:TEMP",
        "$env:LOCALAPPDATA",
        "$env:APPDATA"
    )
    
    $cheatKeywords = @('inject', 'cheat', 'hack', 'client', 'loader', 'mod', 'auto', 'macro', 'bypass')
    $foundFiles = @()
    
    foreach ($path in $searchPaths) {
        if (Test-Path $path) {
            Write-ScanLog "Scanning: $path" "INFO" $logFile
            
            $files = Get-ChildItem -Path $path -Recurse -Include *.exe,*.dll -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) }
            
            foreach ($file in $files) {
                foreach ($keyword in $cheatKeywords) {
                    if ($file.Name.ToLower() -like "*$keyword*") {
                        $foundFiles += $file
                        Write-ScanLog "SUSPICIOUS FILE FOUND!" "ALERT" $logFile
                        Write-ScanLog "  Name: $($file.Name)" "WARN" $logFile
                        Write-ScanLog "  Path: $($file.FullName)" "WARN" $logFile
                        Write-ScanLog "  Size: $($file.Length) bytes" "INFO" $logFile
                        Write-ScanLog "  Modified: $($file.LastWriteTime)" "INFO" $logFile
                        
                        $sig = Get-AuthenticodeSignature $file.FullName
                        if ($sig.Status -ne 'Valid') {
                            Write-ScanLog "  Signature: UNSIGNED/INVALID" "CRITICAL" $logFile
                        }
                        Write-Host ""
                        break
                    }
                }
            }
        }
    }
    
    Write-ScanLog "File search completed!" "SUCCESS" $logFile
    Write-ScanLog "Suspicious files found: $($foundFiles.Count)" "INFO" $logFile
    
    if ($foundFiles.Count -eq 0) {
        Write-ScanLog "No suspicious files found in recent history" "SUCCESS" $logFile
    }
    
    Write-ScanLog "Results saved to: $logFile" "INFO" $logFile
    
    Wait-ForKeyPress
}

# ═══════════════════════════════════════════════════════════
# SCAN 9: VIEW SCAN HISTORY
# ═══════════════════════════════════════════════════════════
function Show-ScanHistory {
    Show-Banner
    Write-Host "  SCAN HISTORY" -ForegroundColor Cyan
    Write-Host "  ════════════════════════════════════════" -ForegroundColor DarkGray
    Write-Host ""
    
    $logFiles = Get-ChildItem -Path $Global:LogDirectory -Filter *.txt | Sort-Object LastWriteTime -Descending
    
    if ($logFiles.Count -eq 0) {
        Write-Host "  No scan logs found." -ForegroundColor Yellow
    } else {
        Write-Host "  Found $($logFiles.Count) scan log(s):`n" -ForegroundColor Cyan
        
        $index = 1
        foreach ($file in $logFiles) {
            Write-Host "  [$index] " -NoNewline -ForegroundColor Yellow
            Write-Host "$($file.Name)" -NoNewline -ForegroundColor White
            Write-Host " ($([math]::Round($file.Length/1KB, 2)) KB)" -ForegroundColor Gray
            $index++
        }
        
        Write-Host ""
        Write-Host "  Enter number to view log (or 0 to return): " -NoNewline -ForegroundColor Gray
        $selection = Read-Host
        
        if ($selection -match '^\d+$' -and [int]$selection -gt 0 -and [int]$selection -le $logFiles.Count) {
            $selectedFile = $logFiles[[int]$selection - 1]
            Clear-Host
            Write-Host ""
            Write-Host "  Viewing: $($selectedFile.Name)" -ForegroundColor Cyan
            Write-Host "  ════════════════════════════════════════" -ForegroundColor DarkGray
            Write-Host ""
            Get-Content $selectedFile.FullName | ForEach-Object {
                Write-Host "  $_" -ForegroundColor White
            }
        }
    }
    
    Wait-ForKeyPress
}

# ═══════════════════════════════════════════════════════════
# MAIN PROGRAM LOOP
# ═══════════════════════════════════════════════════════════
function Start-NoBP {
    while ($true) {
        Show-Menu
        Write-Host "  Select option: " -NoNewline -ForegroundColor Gray
        $choice = Read-Host
        
        switch ($choice) {
            "1" { Start-StringPatternScan }
            "2" { Start-DLLUnloadMonitor }
            "3" { Start-ActiveDLLScan }
            "4" { Start-GUIHookDetection }
            "5" { Start-RealTimeMonitor }
            "6" { Start-CompleteSystemScan }
            "7" { Start-DriverAnalysis }
            "8" { Start-ForensicFileSearch }
            "9" { Show-ScanHistory }
            "0" { 
                Clear-Host
                Write-Host ""
                Write-Host "  Thank you for using NoBP by Wanda!" -ForegroundColor Cyan
                Write-Host ""
                exit 
            }
            default {
                Show-Banner
                Write-Host "  Invalid option. Please try again." -ForegroundColor Red
                Start-Sleep -Seconds 2
            }
        }
    }
}

# Start the program
Start-NoBP
