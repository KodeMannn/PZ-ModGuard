<# :
@echo off
title "Project Zomboid - Java and Binary Mod Guard v2.1"
color 0F
powershell -NoProfile -ExecutionPolicy Bypass -Command "Invoke-Expression ([System.IO.File]::ReadAllText('%~f0'))"
echo.
pause
exit /b
#>

Add-Type -AssemblyName System.IO.Compression.FileSystem

Clear-Host
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "       PROJECT ZOMBOID - ADVANCED JAVA & BINARY MOD GUARD        " -ForegroundColor Cyan
Write-Host "                        Version 2.1.0                            " -ForegroundColor DarkCyan
Write-Host "=================================================================" -ForegroundColor Cyan

# 1. High-Precision JVM Class Constant Pool Parser
function Get-JavaClassConstants($bytes) {
    if ($bytes.Length -lt 10) { return @() }
    if ($bytes[0] -ne 0xCA -or $bytes[1] -ne 0xFE -or $bytes[2] -ne 0xBA -or $bytes[3] -ne 0xBE) {
        return @()
    }
    
    $ms = New-Object System.IO.MemoryStream(,$bytes)
    $reader = New-Object System.IO.BinaryReader($ms)
    $reader.ReadBytes(8) | Out-Null
    
    $b1 = [int]$reader.ReadByte()
    $b2 = [int]$reader.ReadByte()
    $cpCount = ($b1 -shl 8) -bor $b2
    
    $strings = [System.Collections.Generic.List[string]]::new()
    $i = 1
    while ($i -lt $cpCount -and $ms.Position -lt $ms.Length) {
        $tag = $reader.ReadByte()
        switch ($tag) {
            1 { # CONSTANT_Utf8
                $l1 = [int]$reader.ReadByte()
                $l2 = [int]$reader.ReadByte()
                $len = ($l1 -shl 8) -bor $l2
                if ($len -gt 0 -and ($ms.Position + $len) -le $ms.Length) {
                    $strBytes = $reader.ReadBytes($len)
                    $strings.Add([System.Text.Encoding]::UTF8.GetString($strBytes))
                }
                $i++
            }
            3 { $reader.ReadBytes(4) | Out-Null; $i++ }
            4 { $reader.ReadBytes(4) | Out-Null; $i++ }
            5 { $reader.ReadBytes(8) | Out-Null; $i += 2 }
            6 { $reader.ReadBytes(8) | Out-Null; $i += 2 }
            7 { $reader.ReadBytes(2) | Out-Null; $i++ }
            8 { $reader.ReadBytes(2) | Out-Null; $i++ }
            9 { $reader.ReadBytes(4) | Out-Null; $i++ }
            10 { $reader.ReadBytes(4) | Out-Null; $i++ }
            11 { $reader.ReadBytes(4) | Out-Null; $i++ }
            12 { $reader.ReadBytes(4) | Out-Null; $i++ }
            15 { $reader.ReadBytes(3) | Out-Null; $i++ }
            16 { $reader.ReadBytes(2) | Out-Null; $i++ }
            17 { $reader.ReadBytes(4) | Out-Null; $i++ }
            18 { $reader.ReadBytes(4) | Out-Null; $i++ }
            19 { $reader.ReadBytes(2) | Out-Null; $i++ }
            20 { $reader.ReadBytes(2) | Out-Null; $i++ }
            default { $i = $cpCount }
        }
    }
    $reader.Close()
    $ms.Close()
    return $strings
}

# 2. Visual Progress Bar Helper
function Show-ModProgressBar($current, $total, $title) {
    if ($total -le 0) { return }
    $barLength = 26
    $pct = [math]::Min(100, [math]::Max(0, [math]::Round(($current / $total) * 100)))
    $filled = [int][math]::Round(($current / $total) * $barLength)
    $empty = [int]($barLength - $filled)
    $bar = ("=" * $filled) + ("-" * $empty)
    
    $cleanTitle = if ($title.Length -gt 32) { $title.Substring(0, 29) + "..." } else { $title.PadRight(32) }
    Write-Host -NoNewline ("`r  [$bar] $pct% ($current/$total) $cleanTitle")
    Write-Progress -Activity "Project Zomboid Mod Guard" -Status "$cleanTitle ($current of $total)" -PercentComplete $pct
}

function Clear-ModProgressBar() {
    Write-Host -NoNewline ("`r" + (" " * 79) + "`r")
    Write-Progress -Activity "Project Zomboid Mod Guard" -Completed
}

# 3. Multi-Library Steam Auto-Detection
$workshopDirs = @()
try {
    $steamPath = (Get-ItemProperty -Path "HKCU:\Software\Valve\Steam" -ErrorAction SilentlyContinue).SteamPath
    if ($steamPath) {
        $steamPath = $steamPath.Replace('/', '\')
        $vdf = "$steamPath\steamapps\libraryfolders.vdf"
        if (Test-Path $vdf) {
            $content = Get-Content $vdf -Raw
            $matches = [regex]::Matches($content, '\"path\"\s+\"([^\"]+)\"')
            foreach ($m in $matches) {
                $lib = $m.Groups[1].Value.Replace('\\', '\')
                $ws = "$lib\steamapps\workshop\content\108600"
                if (Test-Path $ws) { $workshopDirs += $ws }
            }
        }
    }
} catch {}

if ($workshopDirs.Count -eq 0) {
    $defaults = @(
        "C:\Program Files (x86)\Steam\steamapps\workshop\content\108600",
        "D:\SteamLibrary\steamapps\workshop\content\108600",
        "E:\SteamLibrary\steamapps\workshop\content\108600"
    )
    foreach ($d in $defaults) {
        if (Test-Path $d) { $workshopDirs += $d }
    }
}

if ($workshopDirs.Count -eq 0) {
    Write-Host "`n[!] Could not locate Project Zomboid Workshop directory (AppID 108600)." -ForegroundColor Red
    Write-Host "    Make sure Steam and Project Zomboid are installed." -ForegroundColor Yellow
    return
}

# Pre-Scan Discovery to show item counts
$allJarsCount = 0
$allLooseCount = 0
foreach ($ws in $workshopDirs) {
    $allJarsCount += (Get-ChildItem -Path $ws -Recurse -Filter "*.jar" -ErrorAction SilentlyContinue).Count
    $allLooseCount += (Get-ChildItem -Path $ws -Recurse -Filter "*.class" -ErrorAction SilentlyContinue).Count
}

Write-Host "`nDetected Workshop Libraries:" -ForegroundColor White
foreach ($ws in $workshopDirs) {
    Write-Host "  -> $ws" -ForegroundColor DarkGray
}

Write-Host "`nFound to inspect:" -ForegroundColor White
Write-Host "  - $allJarsCount Java Mod JAR Archives" -ForegroundColor DarkCyan
Write-Host "  - $allLooseCount Loose Class Overrides" -ForegroundColor DarkCyan
Write-Host "  - Mod Folders for Unauthorized Native Binaries (.dll, .exe, scripts)" -ForegroundColor DarkCyan

# USER CONFIRMATION PROMPT
Write-Host ""
$prompt = Read-Host "Press [ENTER] to start scanning, or type [Q] to quit"
if ($prompt -match "^[Qq]") {
    Write-Host "`nScan cancelled by user." -ForegroundColor Yellow
    return
}

Write-Host "`nStarting scan..." -ForegroundColor Green

# 4. Detection Heuristics & Scoped Whitelist Rules
$tier1Patterns = @(
    "discord.com/api/webhooks", "discordapp.com/api/webhooks",
    "api.telegram.org", "pastebin.com/raw", "iplogger", "grabify",
    "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe",
    "certutil", "bitsadmin", "curl.exe",
    "\AppData\Roaming\discord", "\AppData\Local\Google\Chrome", "\AppData\Roaming\Mozilla",
    "Start Menu\Programs\Startup"
)

$tier2Patterns = @(
    "ClassLoader.defineClass", "URLClassLoader",
    "javax/crypto/Cipher", "javax/crypto/spec/SecretKeySpec",
    "java/net/Socket", "java/net/ServerSocket",
    "java/lang/ProcessBuilder", "java/lang/Runtime.getRuntime"
)

$scopedWhitelist = @(
    "ZombieBuddy.jar|ByteBuddyAgent|java/lang/ProcessBuilder",
    "ZombieBuddy.jar|SwingModApprovalFrontend|java/lang/ProcessBuilder",
    "ZombieBuddy.jar|org/bouncycastle|javax/crypto",
    "ZombieBuddy.jar|net/bytebuddy|URLClassLoader",
    "ZombieBuddy.jar|net/bytebuddy|Socket",
    "ZombieBuddy.jar|classgraph|URLClassLoader",
    "ZombieBuddy.jar|MissingEntryException|URLClassLoader",
    "ZombieBuddy.jar|VirtualMachine|Socket",
    "Viewpoint.jar|viewpoint/platform/GpuBusy.class|java/lang/ProcessBuilder",
    "Viewpoint.jar|viewpoint/platform/GpuBusy.class|typeperf",
    "zbNative.dll",
    "PZ_Optimization|Restart.class|powershell.exe",
    "PZ_Optimization|Uninstall.class|powershell.exe",
    "PZ_Optimization|install.ps1"
)

function Test-IsWhitelisted($parentPath, $entryPath, $pattern) {
    foreach ($rule in $scopedWhitelist) {
        $parts = $rule.Split('|')
        if ($parts.Count -eq 3) {
            if ($parentPath -like "*$($parts[0])*" -and $entryPath -like "*$($parts[1])*" -and $pattern -like "*$($parts[2])*") {
                return $true
            }
        } elseif ($parts.Count -eq 2) {
            if ($parentPath -like "*$($parts[0])*" -and $entryPath -like "*$($parts[1])*") {
                return $true
            }
        } elseif ($parts.Count -eq 1) {
            if ($parentPath -like "*$($parts[0])*" -or $entryPath -like "*$($parts[0])*") {
                return $true
            }
        }
    }
    return $false
}

# 5. Scanner Execution
$reportLines = [System.Collections.Generic.List[string]]::new()
$reportLines.Add("Project Zomboid Mod Security Scan Report - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
$reportLines.Add("==========================================================================")

$statsTotalJars = 0
$statsTotalLooseClasses = 0
$statsTotalNative = 0
$statsCritical = 0
$statsWarning = 0

foreach ($ws in $workshopDirs) {
    Write-Host "`nScanning Workshop Location: $ws" -ForegroundColor DarkGray
    $reportLines.Add("Workshop Location: $ws")

    # A. Scan for Unauthorized Native Binaries & Scripts (.exe, .dll, .vbs, .bat)
    $nativeFiles = Get-ChildItem -Path $ws -Recurse -Include *.exe,*.dll,*.vbs,*.bat -Exclude "PZ-ModGuard.bat","Scan-PZMods.bat","install.ps1" -ErrorAction SilentlyContinue
    foreach ($bin in $nativeFiles) {
        $statsTotalNative++
        if (-not (Test-IsWhitelisted $bin.FullName $bin.Name "native")) {
            $statsCritical++
            $msg = "[CRITICAL] Unauthorized Native Binary Detected: $($bin.FullName)"
            Write-Host "`n$msg" -ForegroundColor Red
            $reportLines.Add($msg)
        }
    }

    # B. Scan JAR Packages with Progress Bar
    $jars = Get-ChildItem -Path $ws -Recurse -Filter "*.jar" -ErrorAction SilentlyContinue
    $statsTotalJars += $jars.Count
    $jarIdx = 0

    foreach ($jar in $jars) {
        $jarIdx++
        Show-ModProgressBar $jarIdx $jars.Count $jar.Name

        $jarCritical = @()
        $jarWarning = @()

        try {
            $zip = [System.IO.Compression.ZipFile]::OpenRead($jar.FullName)
            foreach ($entry in $zip.Entries) {
                if ($entry.Name.EndsWith(".class")) {
                    $es = $entry.Open()
                    $ms = New-Object System.IO.MemoryStream
                    $es.CopyTo($ms)
                    $es.Close()
                    
                    $constants = Get-JavaClassConstants $ms.ToArray()
                    $ms.Close()

                    foreach ($c in $constants) {
                        # Check Tier 1 (Critical)
                        foreach ($p in $tier1Patterns) {
                            if ($c.IndexOf($p, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                                if (-not (Test-IsWhitelisted $jar.FullName $entry.FullName $p)) {
                                    $jarCritical += "$($entry.Name) -> contains '$p'"
                                }
                            }
                        }
                        # Check Tier 2 (Warning)
                        foreach ($p in $tier2Patterns) {
                            if ($c.IndexOf($p, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                                if (-not (Test-IsWhitelisted $jar.FullName $entry.FullName $p)) {
                                    $jarWarning += "$($entry.Name) -> calls '$p'"
                                }
                            }
                        }
                    }
                }
            }
            $zip.Dispose()
        } catch {
            Clear-ModProgressBar
            Write-Host "  [?] Notice: Could not read $($jar.Name) (file locked or in use)." -ForegroundColor Yellow
            continue
        }

        Clear-ModProgressBar
        if ($jarCritical.Count -gt 0) {
            $statsCritical++
            Write-Host "  [CRITICAL THREAT] $($jar.Name)" -ForegroundColor Red
            Write-Host "    Path: $($jar.FullName)" -ForegroundColor DarkGray
            $reportLines.Add("[CRITICAL THREAT] $($jar.FullName)")
            $jarCritical | Select-Object -Unique | ForEach-Object {
                Write-Host "    [!] $_" -ForegroundColor Red
                $reportLines.Add("    - $_")
            }
        } elseif ($jarWarning.Count -gt 0) {
            $statsWarning++
            Write-Host "  [WARNING / SUSPICIOUS] $($jar.Name)" -ForegroundColor Yellow
            Write-Host "    Path: $($jar.FullName)" -ForegroundColor DarkGray
            $reportLines.Add("[WARNING / SUSPICIOUS] $($jar.FullName)")
            $jarWarning | Select-Object -Unique | ForEach-Object {
                Write-Host "    [*] $_" -ForegroundColor Yellow
                $reportLines.Add("    - $_")
            }
        } else {
            Write-Host "  [OK] $($jar.Name)" -ForegroundColor Green
            $reportLines.Add("  [OK] $($jar.Name)")
        }
    }

    # C. Scan Loose .class Files with Progress Bar
    $looseClasses = Get-ChildItem -Path $ws -Recurse -Filter "*.class" -ErrorAction SilentlyContinue
    if ($looseClasses.Count -gt 0) {
        $statsTotalLooseClasses += $looseClasses.Count
        $looseFlagged = @()
        $cIdx = 0

        foreach ($cf in $looseClasses) {
            $cIdx++
            if ($cIdx % 25 -eq 0 -or $cIdx -eq $looseClasses.Count) {
                Show-ModProgressBar $cIdx $looseClasses.Count "Checking loose classes ($cIdx/$($looseClasses.Count))"
            }
            try {
                $bytes = [System.IO.File]::ReadAllBytes($cf.FullName)
                $constants = Get-JavaClassConstants $bytes
                foreach ($c in $constants) {
                    foreach ($p in $tier1Patterns) {
                        if ($c.IndexOf($p, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                            if (-not (Test-IsWhitelisted $cf.FullName $cf.Name $p)) {
                                $looseFlagged += "$($cf.Name) -> $p"
                            }
                        }
                    }
                }
            } catch {}
        }
        Clear-ModProgressBar
        if ($looseFlagged.Count -gt 0) {
            $statsCritical++
            Write-Host "  [CRITICAL THREAT] Loose .class files flagged:" -ForegroundColor Red
            $looseFlagged | Select-Object -Unique | ForEach-Object {
                Write-Host "    [!] $_" -ForegroundColor Red
                $reportLines.Add("  [!] Loose Class: $_")
            }
        } else {
            Write-Host "  [OK] All $($looseClasses.Count) loose .class files clean." -ForegroundColor Green
            $reportLines.Add("  [OK] All $($looseClasses.Count) loose .class files clean.")
        }
    }
}

# 6. Final Audit Summary
Write-Host "`n=================================================================" -ForegroundColor Cyan
Write-Host "                        AUDIT SUMMARY                            " -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "Scanned Libraries: $($workshopDirs.Count)"
Write-Host "JAR Packages:      $statsTotalJars"
Write-Host "Loose Class Files: $statsTotalLooseClasses"
Write-Host "Native Binaries:   $statsTotalNative"

if ($statsCritical -eq 0 -and $statsWarning -eq 0) {
    Write-Host "`nRESULT: ALL MODS CLEAN. No threats or suspicious behaviors detected." -ForegroundColor Green
} elseif ($statsCritical -eq 0 -and $statsWarning -gt 0) {
    Write-Host "`nRESULT: CAUTION. $statsWarning mod(s) have suspicious indicators requiring review." -ForegroundColor Yellow
} else {
    Write-Host "`nRESULT: DANGER! $statsCritical critical threat(s) detected! Do not launch game." -ForegroundColor Red
}

$reportPath = ".\pz_mod_scan_report.txt"
try {
    [System.IO.File]::WriteAllLines($reportPath, $reportLines)
    Write-Host "`nDetailed report saved to: $reportPath" -ForegroundColor DarkGray
} catch {}
