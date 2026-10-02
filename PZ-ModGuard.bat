<# :
@echo off
title "Project Zomboid - Java and Binary Mod Guard v2.2.0"
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
Write-Host "                        Version 2.2.0                            " -ForegroundColor DarkCyan
Write-Host "            Discord: https://discord.gg/5rmsnwMPez               " -ForegroundColor DarkGray
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
    Write-Host -NoNewline ("`r" + (" " * 80) + "`r")
    Write-Progress -Activity "Project Zomboid Mod Guard" -Completed
}

# 3. Multi-Target Path Discovery (Workshop, Main Game Root, and Local User Mods)
$targets = @{
    Workshop = [System.Collections.Generic.List[string]]::new()
    GameRoot = [System.Collections.Generic.List[string]]::new()
    UserMods = [System.Collections.Generic.List[string]]::new()
}

$steamPath = (Get-ItemProperty -Path "HKCU:\Software\Valve\Steam" -ErrorAction SilentlyContinue).SteamPath
if (-not $steamPath) {
    $steamPath = (Get-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Valve\Steam" -ErrorAction SilentlyContinue).InstallPath
}
if (-not $steamPath) {
    $steamPath = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Valve\Steam" -ErrorAction SilentlyContinue).InstallPath
}

$libraryRoots = [System.Collections.Generic.List[string]]::new()
if ($steamPath) {
    $steamPath = $steamPath.Replace('/', '\')
    $vdf = "$steamPath\steamapps\libraryfolders.vdf"
    if (Test-Path $vdf) {
        $content = Get-Content $vdf -Raw
        $matches = [regex]::Matches($content, '\"path\"\s+\"([^\"]+)\"')
        foreach ($m in $matches) {
            $libraryRoots.Add($m.Groups[1].Value.Replace('\\', '\'))
        }
    }
}

if ($libraryRoots.Count -eq 0) {
    $libraryRoots.AddRange(@(
        "C:\Program Files (x86)\Steam",
        "D:\SteamLibrary",
        "E:\SteamLibrary"
    ))
}

foreach ($lib in $libraryRoots) {
    $ws = "$lib\steamapps\workshop\content\108600"
    if (Test-Path $ws) { $targets.Workshop.Add($ws) }
    
    $gm = "$lib\steamapps\common\ProjectZomboid"
    if (Test-Path $gm) { $targets.GameRoot.Add($gm) }
}

$um = "$env:USERPROFILE\Zomboid\mods"
if (Test-Path $um) { $targets.UserMods.Add($um) }

if ($targets.Workshop.Count -eq 0 -and $targets.GameRoot.Count -eq 0) {
    Write-Host "`n[!] Could not locate Project Zomboid installation or workshop directory." -ForegroundColor Red
    Write-Host "    Make sure Steam and Project Zomboid are installed." -ForegroundColor Yellow
    return
}

# 4. Stock Engine Files & Whitelist Rules
$stockPzDlls = @(
    "bink2w64.dll", "bink64.dll", "fmod.dll", "fmodintegration64.dll", "fmodintegration32.dll",
    "fmodstudio.dll", "fmod32.dll", "imgui-java64.dll", "jassimp64.dll", "jnidispatch.dll",
    "Lighting64.dll", "Lighting32.dll", "PZBullet64.dll", "PZBullet32.dll", "PZClipper64.dll",
    "PZClipper32.dll", "PZPathFind64.dll", "PZPathFind32.dll", "PZPopMan64.dll", "PZPopMan32.dll",
    "RakNet64.dll", "RakNet32.dll", "steam_api64.dll", "steam_api.dll", "ZNetJNI64.dll",
    "ZNetJNI32.dll", "ZNetNoSteam64.dll", "ZNetNoSteam32.dll"
)
$stockPzJars = @("projectzomboid.jar")
$stockPzScripts = @(
    "ProjectZomboid64.bat", "ProjectZomboid32.bat", "ProjectZomboid64ShowConsole.bat",
    "ProjectZomboidOpenGLDebug64.bat", "ProjectZomboidServer.bat"
)
$whitelistedAgents = @("-agentlib:zbNative")

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
    "PZ_Optimization|Restart.class|java/lang/ProcessBuilder",
    "PZ_Optimization|Uninstall.class|java/lang/ProcessBuilder",
    "PZ_Optimization|SoundProbe.class|java/lang/ProcessBuilder",
    "PZ_Optimization|GameWindow.class|java/lang/ProcessBuilder",
    "PZ_Optimization|install.ps1",
    "ProjectZomboid64.json.pzopt-backup"
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

# Pre-Scan Discovery Count
$allJars = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
$allLooseClasses = [System.Collections.Generic.List[System.IO.FileInfo]]::new()

foreach ($ws in $targets.Workshop) {
    Get-ChildItem -Path $ws -Recurse -Filter "*.jar" -ErrorAction SilentlyContinue | ForEach-Object { $allJars.Add($_) }
    Get-ChildItem -Path $ws -Recurse -Filter "*.class" -ErrorAction SilentlyContinue | ForEach-Object { $allLooseClasses.Add($_) }
}
foreach ($gm in $targets.GameRoot) {
    Get-ChildItem -Path $gm -Filter "*.jar" -ErrorAction SilentlyContinue | Where-Object { $stockPzJars -notcontains $_.Name } | ForEach-Object { $allJars.Add($_) }
    Get-ChildItem -Path $gm -Recurse -Filter "*.class" -Exclude "jre64" -ErrorAction SilentlyContinue | ForEach-Object { $allLooseClasses.Add($_) }
}
foreach ($um in $targets.UserMods) {
    Get-ChildItem -Path $um -Recurse -Filter "*.jar" -ErrorAction SilentlyContinue | ForEach-Object { $allJars.Add($_) }
    Get-ChildItem -Path $um -Recurse -Filter "*.class" -ErrorAction SilentlyContinue | ForEach-Object { $allLooseClasses.Add($_) }
}

Write-Host "`nScanning Targets Discovered:" -ForegroundColor White
if ($targets.Workshop.Count -gt 0) {
    Write-Host "  [Steam Workshop Mods] ($($targets.Workshop.Count) Location):" -ForegroundColor Cyan
    $targets.Workshop | ForEach-Object { Write-Host "    -> $_" -ForegroundColor DarkGray }
}
if ($targets.GameRoot.Count -gt 0) {
    Write-Host "  [Main Game Directory] ($($targets.GameRoot.Count) Location):" -ForegroundColor Cyan
    $targets.GameRoot | ForEach-Object { Write-Host "    -> $_" -ForegroundColor DarkGray }
}
if ($targets.UserMods.Count -gt 0) {
    Write-Host "  [Local User Mods] ($($targets.UserMods.Count) Location):" -ForegroundColor Cyan
    $targets.UserMods | ForEach-Object { Write-Host "    -> $_" -ForegroundColor DarkGray }
}

Write-Host "`nItems Queued for Inspection:" -ForegroundColor White
Write-Host "  - $($allJars.Count) Mod JAR Archives (Workshop & Game Root)" -ForegroundColor DarkCyan
Write-Host "  - $($allLooseClasses.Count) Loose Class Overrides" -ForegroundColor DarkCyan
Write-Host "  - Main Game Launcher Config (ProjectZomboid64.json)" -ForegroundColor DarkCyan
Write-Host "  - All Locations for Rogue Native Binaries (.dll, .exe, scripts)" -ForegroundColor DarkCyan

# USER CONFIRMATION PROMPT
Write-Host ""
$prompt = Read-Host "Press [ENTER] to start scanning, or type [Q] to quit"
if ($prompt -match "^[Qq]") {
    Write-Host "`nScan cancelled by user." -ForegroundColor Yellow
    return
}

Write-Host "`nStarting comprehensive scan..." -ForegroundColor Green

$reportLines = [System.Collections.Generic.List[string]]::new()
$reportLines.Add("Project Zomboid Mod Security Scan Report - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
$reportLines.Add("==========================================================================")

$statsCritical = 0
$statsWarning = 0

# 5. EXECUTION A: Audit Game Root Directories
foreach ($gm in $targets.GameRoot) {
    Write-Host "`nAuditing Main Game Directory: $gm" -ForegroundColor DarkGray
    $reportLines.Add("Main Game Directory: $gm")

    # A.1. Launcher JSON Agent Audit
    $jsonPath = "$gm\ProjectZomboid64.json"
    if (Test-Path $jsonPath) {
        try {
            $cfg = Get-Content $jsonPath -Raw | ConvertFrom-Json
            if ($cfg.vmArgs) {
                foreach ($arg in $cfg.vmArgs) {
                    if ($arg -match "^-(agentlib|agentpath|javaagent):(.*)$") {
                        if ($whitelistedAgents -notcontains $arg) {
                            $statsCritical++
                            $msg = "[CRITICAL] Unauthorized JVM Agent Injected into ProjectZomboid64.json: $arg"
                            Write-Host "  $msg" -ForegroundColor Red
                            $reportLines.Add("  $msg")
                        }
                    }
                }
            }
        } catch {}
    }

    # A.2. Audit Native Binaries in Game Root
    $natives = Get-ChildItem -Path "$gm\*" -Include *.dll,*.exe,*.bat,*.cmd,*.ps1,*.vbs -Exclude "PZ-ModGuard.bat","Scan-PZMods.bat" -ErrorAction SilentlyContinue
    foreach ($n in $natives) {
        $isStock = ($stockPzDlls -contains $n.Name -or $stockPzScripts -contains $n.Name -or $n.Name -like "ProjectZomboid*.exe")
        if (-not $isStock -and -not (Test-IsWhitelisted $n.FullName $n.Name "native")) {
            $statsCritical++
            $msg = "[CRITICAL] Unauthorized Native Binary in Game Root: $($n.FullName)"
            Write-Host "  $msg" -ForegroundColor Red
            $reportLines.Add("  $msg")
        }
    }
}

# 6. EXECUTION B: Audit Native Binaries in Workshop & User Mod Dirs
$nonRootDirs = @()
$nonRootDirs += $targets.Workshop
$nonRootDirs += $targets.UserMods

foreach ($dir in $nonRootDirs) {
    $natives = Get-ChildItem -Path $dir -Recurse -Include *.exe,*.dll,*.vbs,*.bat,*.cmd,*.ps1 -Exclude "PZ-ModGuard.bat","Scan-PZMods.bat","install.ps1" -ErrorAction SilentlyContinue
    foreach ($n in $natives) {
        if (-not (Test-IsWhitelisted $n.FullName $n.Name "native")) {
            $statsCritical++
            $msg = "[CRITICAL] Unauthorized Native Binary Detected: $($n.FullName)"
            Write-Host "  $msg" -ForegroundColor Red
            $reportLines.Add("  $msg")
        }
    }
}

# 7. EXECUTION C: Scan JAR Packages with Progress Bar
Write-Host "`nScanning $($allJars.Count) Mod JAR Packages..." -ForegroundColor DarkGray
$jarIdx = 0

foreach ($jar in $allJars) {
    $jarIdx++
    Show-ModProgressBar $jarIdx $allJars.Count $jar.Name

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
                    foreach ($p in $tier1Patterns) {
                        if ($c.IndexOf($p, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                            if (-not (Test-IsWhitelisted $jar.FullName $entry.FullName $p)) {
                                $jarCritical += "$($entry.Name) -> contains '$p'"
                            }
                        }
                    }
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
        Write-Host "  [OK] $($jar.Name) ($($jar.Directory.Name))" -ForegroundColor Green
        $reportLines.Add("  [OK] $($jar.FullName)")
    }
}

# 8. EXECUTION D: Scan Loose .class Files with Progress Bar
if ($allLooseClasses.Count -gt 0) {
    Write-Host "`nScanning $($allLooseClasses.Count) Loose Class Overrides..." -ForegroundColor DarkGray
    $looseCritical = @()
    $looseWarning = @()
    $cIdx = 0

    foreach ($cf in $allLooseClasses) {
        $cIdx++
        if ($cIdx % 25 -eq 0 -or $cIdx -eq $allLooseClasses.Count) {
            Show-ModProgressBar $cIdx $allLooseClasses.Count "Checking loose classes ($cIdx/$($allLooseClasses.Count))"
        }
        try {
            $bytes = [System.IO.File]::ReadAllBytes($cf.FullName)
            $constants = Get-JavaClassConstants $bytes
            foreach ($c in $constants) {
                foreach ($p in $tier1Patterns) {
                    if ($c.IndexOf($p, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                        if (-not (Test-IsWhitelisted $cf.FullName $cf.Name $p)) {
                            $looseCritical += "$($cf.Name) -> $p"
                        }
                    }
                }
                foreach ($p in $tier2Patterns) {
                    if ($c.IndexOf($p, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                        if (-not (Test-IsWhitelisted $cf.FullName $cf.Name $p)) {
                            $looseWarning += "$($cf.Name) -> $p"
                        }
                    }
                }
            }
        } catch {}
    }
    Clear-ModProgressBar
    if ($looseCritical.Count -gt 0) {
        $statsCritical++
        Write-Host "  [CRITICAL THREAT] Loose .class files flagged:" -ForegroundColor Red
        $looseCritical | Select-Object -Unique | ForEach-Object {
            Write-Host "    [!] $_" -ForegroundColor Red
            $reportLines.Add("  [!] Loose Class: $_")
        }
    } elseif ($looseWarning.Count -gt 0) {
        $statsWarning++
        Write-Host "  [WARNING / SUSPICIOUS] Loose .class files flagged:" -ForegroundColor Yellow
        $looseWarning | Select-Object -Unique | ForEach-Object {
            Write-Host "    [*] $_" -ForegroundColor Yellow
            $reportLines.Add("  [*] Loose Class: $_")
        }
    } else {
        Write-Host "  [OK] All $($allLooseClasses.Count) loose .class files clean." -ForegroundColor Green
        $reportLines.Add("  [OK] All $($allLooseClasses.Count) loose .class files clean.")
    }
}

# 9. Final Audit Summary
Write-Host "`n=================================================================" -ForegroundColor Cyan
Write-Host "                        AUDIT SUMMARY                            " -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "Workshop Locations:    $($targets.Workshop.Count)"
Write-Host "Game Root Locations:   $($targets.GameRoot.Count)"
Write-Host "User Mod Locations:    $($targets.UserMods.Count)"
Write-Host "Total Mod JARs:        $($allJars.Count)"
Write-Host "Loose Class Overrides: $($allLooseClasses.Count)"

if ($statsCritical -eq 0 -and $statsWarning -eq 0) {
    Write-Host "`nRESULT: ALL TARGETS CLEAN. No threats or unauthorized modifications detected." -ForegroundColor Green
} elseif ($statsCritical -eq 0 -and $statsWarning -gt 0) {
    Write-Host "`nRESULT: CAUTION. $statsWarning item(s) have suspicious indicators requiring review." -ForegroundColor Yellow
} else {
    Write-Host "`nRESULT: DANGER! $statsCritical critical threat(s) detected! Do not launch game." -ForegroundColor Red
}

$reportPath = ".\pz_mod_scan_report.txt"
try {
    [System.IO.File]::WriteAllLines($reportPath, $reportLines)
    Write-Host "`nDetailed report saved to: $reportPath" -ForegroundColor DarkGray
} catch {}
