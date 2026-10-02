<# :
@echo off
title "Project Zomboid - Java and Binary Mod Guard v2.5.0"
color 0F
powershell -NoProfile -ExecutionPolicy Bypass -Command "Invoke-Expression ([System.IO.File]::ReadAllText('%~f0'))"
echo.
pause
exit /b
#>

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$encoding = [System.Text.Encoding]::GetEncoding("ISO-8859-1")

Clear-Host
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "       PROJECT ZOMBOID - ADVANCED JAVA & BINARY MOD GUARD        " -ForegroundColor Cyan
Write-Host "                        Version 2.5.0                            " -ForegroundColor DarkCyan
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

# 3. Multi-Target Path Discovery (Workshop, Main Game Root, GOG, and Local User Mods)
$targets = @{
    Workshop = [System.Collections.Generic.List[string]]::new()
    GameRoot = [System.Collections.Generic.List[string]]::new()
    UserMods = [System.Collections.Generic.List[string]]::new()
}

# 3.1. Portable Execution Check (Running directly inside a PZ installation directory)
$currentDir = (Get-Location).Path
if ((Test-Path "$currentDir\projectzomboid.jar") -or (Test-Path "$currentDir\ProjectZomboid64.exe")) {
    if (-not $targets.GameRoot.Contains($currentDir)) { $targets.GameRoot.Add($currentDir) }
}

# 3.2. Steam Multi-Drive Library Auto-Discovery
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
    if (Test-Path $ws) { if (-not $targets.Workshop.Contains($ws)) { $targets.Workshop.Add($ws) } }
    
    $gm = "$lib\steamapps\common\ProjectZomboid"
    if (Test-Path $gm) { if (-not $targets.GameRoot.Contains($gm)) { $targets.GameRoot.Add($gm) } }
}

# 3.3. GOG Galaxy Registry & Standalone Auto-Discovery
$gogRegs = @(
    "HKLM:\SOFTWARE\GOG.com\Games\*",
    "HKLM:\SOFTWARE\WOW6432Node\GOG.com\Games\*"
)
foreach ($reg in $gogRegs) {
    Get-ItemProperty -Path $reg -ErrorAction SilentlyContinue | ForEach-Object {
        $p = $_.PATH
        if (-not $p) { $p = $_.gamePath }
        if (-not $p) { $p = $_.InstallDir }
        if ($p -and (Test-Path $p)) {
            if ((Test-Path "$p\projectzomboid.jar") -or (Test-Path "$p\ProjectZomboid64.exe")) {
                if (-not $targets.GameRoot.Contains($p)) { $targets.GameRoot.Add($p) }
            }
        }
    }
}

$commonGogPaths = @(
    "C:\GOG Games\Project Zomboid",
    "D:\GOG Games\Project Zomboid",
    "E:\GOG Games\Project Zomboid",
    "C:\Program Files (x86)\GOG Galaxy\Games\Project Zomboid",
    "D:\GOG Galaxy\Games\Project Zomboid",
    "E:\GOG Galaxy\Games\Project Zomboid",
    "C:\Games\Project Zomboid",
    "D:\Games\Project Zomboid"
)
foreach ($p in $commonGogPaths) {
    if (Test-Path $p) {
        if ((Test-Path "$p\projectzomboid.jar") -or (Test-Path "$p\ProjectZomboid64.exe")) {
            if (-not $targets.GameRoot.Contains($p)) { $targets.GameRoot.Add($p) }
        }
    }
}

# 3.4. Local User Mods (%USERPROFILE%\Zomboid\mods)
$um = "$env:USERPROFILE\Zomboid\mods"
if (Test-Path $um) { if (-not $targets.UserMods.Contains($um)) { $targets.UserMods.Add($um) } }

# 3.5. In-Game Directory Mods (<GameRoot>\mods)
foreach ($gm in $targets.GameRoot) {
    $gmMods = "$gm\mods"
    if ((Test-Path $gmMods) -and (-not $targets.UserMods.Contains($gmMods))) {
        $targets.UserMods.Add($gmMods)
    }
}

# 3.6. Interactive Fallback Prompt if Nothing Discovered (GOG / Non-Steam / Custom Drive)
if ($targets.Workshop.Count -eq 0 -and $targets.GameRoot.Count -eq 0) {
    Write-Host "`n[!] Could not automatically locate a Steam or GOG installation of Project Zomboid." -ForegroundColor Yellow
    Write-Host "    You can manually specify your Project Zomboid directory (GOG, standalone, or custom drive)." -ForegroundColor Cyan
    Write-Host ""
    $fallbackInput = Read-Host "Enter path to Project Zomboid directory (or drag folder here, or [Q] to quit)"
    if ($fallbackInput -match "^[Qq]" -or [string]::IsNullOrWhiteSpace($fallbackInput)) {
        Write-Host "`nScan cancelled." -ForegroundColor Yellow
        return
    }
    $cleanPath = $fallbackInput.Trim().Trim('"').Trim("'")
    if (Test-Path $cleanPath) {
        $targets.GameRoot.Add($cleanPath)
        $gmMods = "$cleanPath\mods"
        if (Test-Path $gmMods) { $targets.UserMods.Add($gmMods) }
        Write-Host "  [+] Added Custom Game Directory: $cleanPath" -ForegroundColor Green
    } else {
        Write-Host "`n[!] Directory not found: $cleanPath" -ForegroundColor Red
        return
    }
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
    "projectzomboid.jar|org/javacord|discord.com/api/webhooks",
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

$stockPzPackages = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
@(
    "astar", "com", "de", "fmod", "generation", "gnu", "imgui", "io",
    "jassimp", "javax", "kotlin", "META-INF", "N3D", "okhttp3", "okio",
    "org", "oshi", "pl", "se", "windows", "macos", "linux", "zombie"
) | ForEach-Object { [void]$stockPzPackages.Add($_) }

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

function Audit-PzEngine($gm, $reportLines) {
    $pzJarPath = "$gm\projectzomboid.jar"
    if (-not (Test-Path $pzJarPath)) {
        return $null
    }

    Write-Host "`nAuditing Base Game Engine (projectzomboid.jar)..." -ForegroundColor Cyan
    $reportLines.Add("Base Game Engine Audit: $pzJarPath")

    $pzCritical = [System.Collections.Generic.List[string]]::new()
    $pzNonStockClasses = [System.Collections.Generic.List[string]]::new()
    $pzNonStockPackages = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $pzInjectedWarnings = [System.Collections.Generic.List[string]]::new()

    try {
        $zip = [System.IO.Compression.ZipFile]::OpenRead($pzJarPath)
        $classEntries = [System.Collections.Generic.List[System.IO.Compression.ZipArchiveEntry]]::new()

        foreach ($entry in $zip.Entries) {
            if ($entry.FullName.EndsWith(".class")) {
                $classEntries.Add($entry)
                $parts = $entry.FullName.Split('/')
                $root = $parts[0]
                if (-not $stockPzPackages.Contains($root)) {
                    $pzNonStockClasses.Add($entry.FullName)
                    $pkg = if ($parts.Length -gt 2) { "$($parts[0]).$($parts[1])" } else { $parts[0] }
                    [void]$pzNonStockPackages.Add($pkg)
                }
            }
        }

        $encoding = [System.Text.Encoding]::GetEncoding("ISO-8859-1")
        $idx = 0
        $total = $classEntries.Count

        foreach ($entry in $classEntries) {
            $idx++
            if ($idx % 1000 -eq 0 -or $idx -eq $total) {
                Show-ModProgressBar $idx $total "Auditing projectzomboid.jar"
            }

            $stream = $entry.Open()
            $reader = New-Object System.IO.StreamReader($stream, $encoding)
            $content = $reader.ReadToEnd()
            $reader.Dispose()
            $stream.Dispose()

            # Check Tier 1 malicious payloads
            foreach ($p in $tier1Patterns) {
                if ($content.IndexOf($p, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                    if (-not (Test-IsWhitelisted "projectzomboid.jar" $entry.FullName $p)) {
                        $pzCritical.Add("$($entry.FullName) -> contains '$p'")
                    }
                }
            }

            # Check Tier 2 exclusively for non-stock injected mod classes
            $parts = $entry.FullName.Split('/')
            if (-not $stockPzPackages.Contains($parts[0])) {
                foreach ($p in $tier2Patterns) {
                    if ($content.IndexOf($p, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                        if (-not (Test-IsWhitelisted "projectzomboid.jar" $entry.FullName $p)) {
                            $pzInjectedWarnings.Add("$($entry.FullName) -> calls '$p'")
                        }
                    }
                }
            }
        }
        $zip.Dispose()
        Clear-ModProgressBar
    } catch {
        Clear-ModProgressBar
        Write-Host "  [?] Notice: Could not read projectzomboid.jar (file locked or in use)." -ForegroundColor Yellow
        return $null
    }

    if ($pzCritical.Count -gt 0) {
        Write-Host "  [CRITICAL THREAT] Base Game Engine Compromised: $pzJarPath" -ForegroundColor Red
        $reportLines.Add("  [CRITICAL THREAT] Base Game Engine Compromised: $pzJarPath")
        $pzCritical | Select-Object -Unique | ForEach-Object {
            Write-Host "    [!] $_" -ForegroundColor Red
            $reportLines.Add("    - $_")
        }
        Write-Host "    [!] ACTION REQUIRED: Run Steam 'Verify integrity of game files' immediately to restore clean official game files." -ForegroundColor Yellow
        $reportLines.Add("    - ACTION REQUIRED: Verify integrity of game files via Steam.")
    } elseif ($pzNonStockPackages.Count -gt 0) {
        Write-Host "  [i] Notice: projectzomboid.jar contains 3rd-party mod patches ($($pzNonStockPackages -join ', '))" -ForegroundColor Cyan
        $reportLines.Add("  [i] Notice: projectzomboid.jar contains 3rd-party mod patches ($($pzNonStockPackages -join ', '))")
        if ($pzInjectedWarnings.Count -gt 0) {
            Write-Host "  [WARNING / SUSPICIOUS] Injected mod classes contain elevated capabilities:" -ForegroundColor Yellow
            $reportLines.Add("  [WARNING / SUSPICIOUS] Injected mod classes contain elevated capabilities:")
            $pzInjectedWarnings | Select-Object -Unique | ForEach-Object {
                Write-Host "    [*] $_" -ForegroundColor Yellow
                $reportLines.Add("    - $_")
            }
        } else {
            Write-Host "  [OK] Injected mod patches verified clean (0 malicious payloads)." -ForegroundColor Green
            $reportLines.Add("  [OK] Injected mod patches verified clean (0 malicious payloads).")
        }
    } else {
        Write-Host "  [OK] Base Engine Verified Clean: projectzomboid.jar ($total classes verified, 0 threats)" -ForegroundColor Green
        $reportLines.Add("  [OK] Base Engine Verified Clean: projectzomboid.jar ($total classes verified, 0 threats)")
    }

    return [PSCustomObject]@{
        Critical = $pzCritical.Count
        Warnings = $pzInjectedWarnings.Count
        NonStock = $pzNonStockPackages.Count
        Classes  = $total
    }
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

# USER SCAN PROFILE SELECTION
Write-Host "`n=================================================================" -ForegroundColor Cyan
Write-Host "                      SELECT SCAN PROFILE                        " -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  [1] Quick Scan      - Workshop & User Mods (Fastest, ~1.5s) [DEFAULT]" -ForegroundColor White
Write-Host "  [2] Full Deep Scan  - Complete Audit (Base Engine + Workshop + Overrides)" -ForegroundColor White
Write-Host "  [3] Base Engine     - projectzomboid.jar Integrity & Security Audit" -ForegroundColor White
Write-Host "  [4] Custom Target   - Scan a specific Mod Folder or .JAR file" -ForegroundColor White
Write-Host "  [5] Custom Game Dir - Point to a GOG / Standalone / Custom PZ Folder" -ForegroundColor White
Write-Host "  [Q] Quit / Cancel" -ForegroundColor DarkGray
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host ""
$prompt = Read-Host "Press [ENTER] for Quick Scan [1], or enter [1-5, Q]"
if ($prompt -match "^[Qq]") {
    Write-Host "`nScan cancelled by user." -ForegroundColor Yellow
    return
}
$choice = if ([string]::IsNullOrWhiteSpace($prompt)) { "1" } else { $prompt.Trim() }

$scanProfileName = "Quick Scan"
$doScanEngine = $false
$doScanWorkshop = $false
$doScanUserMods = $false
$doScanLooseClasses = $false
$doScanLauncher = $false
$customPath = $null

switch ($choice) {
    "1" {
        $scanProfileName = "Quick Scan"
        $doScanWorkshop = $true
        $doScanUserMods = $true
        $doScanLauncher = $true
        $doScanLooseClasses = $false
        $doScanEngine = $false
    }
    "2" {
        $scanProfileName = "Full Deep Scan"
        $doScanWorkshop = $true
        $doScanUserMods = $true
        $doScanLauncher = $true
        $doScanLooseClasses = $true
        $doScanEngine = $true
    }
    "3" {
        $scanProfileName = "Base Game Engine Audit"
        $doScanEngine = $true
        $doScanLauncher = $true
        $doScanWorkshop = $false
        $doScanUserMods = $false
        $doScanLooseClasses = $false
    }
    "4" {
        $scanProfileName = "Custom Target Scan"
        Write-Host ""
        $customInput = Read-Host "Enter or drag-and-drop the path to the Mod folder or .JAR file"
        $customInput = $customInput.Trim().Trim('"').Trim("'")
        if (-not (Test-Path $customInput)) {
            Write-Host "`n[!] Path not found: $customInput" -ForegroundColor Red
            return
        }
        $customPath = $customInput
    }
    "5" {
        $scanProfileName = "Custom Game Directory Audit"
        Write-Host ""
        $customPz = Read-Host "Enter path to Project Zomboid directory (or drag folder here)"
        $customPz = $customPz.Trim().Trim('"').Trim("'")
        if (-not (Test-Path $customPz)) {
            Write-Host "`n[!] Directory not found: $customPz" -ForegroundColor Red
            return
        }
        $targets.GameRoot.Clear()
        $targets.GameRoot.Add($customPz)
        if (Test-Path "$customPz\mods") {
            if (-not $targets.UserMods.Contains("$customPz\mods")) { $targets.UserMods.Add("$customPz\mods") }
        }
        $doScanEngine = $true
        $doScanWorkshop = $false
        $doScanUserMods = $true
        $doScanLauncher = $true
        $doScanLooseClasses = $true
    }
    default {
        Write-Host "`nUnrecognized option '$choice'. Defaulting to [1] Quick Scan." -ForegroundColor Yellow
        $scanProfileName = "Quick Scan"
        $doScanWorkshop = $true
        $doScanUserMods = $true
        $doScanLauncher = $true
        $doScanLooseClasses = $false
        $doScanEngine = $false
    }
}

$allJars = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
$allLooseClasses = [System.Collections.Generic.List[System.IO.FileInfo]]::new()

if ($customPath) {
    if ((Get-Item $customPath) -is [System.IO.FileInfo]) {
        if ($customPath.EndsWith(".jar", [System.StringComparison]::OrdinalIgnoreCase)) {
            $allJars.Add((Get-Item $customPath))
        } elseif ($customPath.EndsWith(".class", [System.StringComparison]::OrdinalIgnoreCase)) {
            $allLooseClasses.Add((Get-Item $customPath))
        }
    } else {
        Get-ChildItem -Path $customPath -Recurse -Filter "*.jar" -ErrorAction SilentlyContinue | ForEach-Object { $allJars.Add($_) }
        Get-ChildItem -Path $customPath -Recurse -Filter "*.class" -ErrorAction SilentlyContinue | ForEach-Object { $allLooseClasses.Add($_) }
    }
} else {
    if ($doScanWorkshop) {
        foreach ($ws in $targets.Workshop) {
            Get-ChildItem -Path $ws -Recurse -Filter "*.jar" -ErrorAction SilentlyContinue | ForEach-Object { $allJars.Add($_) }
            if ($doScanLooseClasses) {
                Get-ChildItem -Path $ws -Recurse -Filter "*.class" -ErrorAction SilentlyContinue | ForEach-Object { $allLooseClasses.Add($_) }
            }
        }
    }
    if ($doScanUserMods) {
        foreach ($um in $targets.UserMods) {
            Get-ChildItem -Path $um -Recurse -Filter "*.jar" -ErrorAction SilentlyContinue | ForEach-Object { $allJars.Add($_) }
            if ($doScanLooseClasses) {
                Get-ChildItem -Path $um -Recurse -Filter "*.class" -ErrorAction SilentlyContinue | ForEach-Object { $allLooseClasses.Add($_) }
            }
        }
    }
    if ($doScanEngine) {
        foreach ($gm in $targets.GameRoot) {
            Get-ChildItem -Path $gm -Filter "*.jar" -ErrorAction SilentlyContinue | Where-Object { $stockPzJars -notcontains $_.Name } | ForEach-Object { $allJars.Add($_) }
            if ($doScanLooseClasses) {
                Get-ChildItem -Path $gm -Recurse -Filter "*.class" -Exclude "jre64" -ErrorAction SilentlyContinue | ForEach-Object { $allLooseClasses.Add($_) }
            }
        }
    }
}

Write-Host "`nProfile Selected: $scanProfileName" -ForegroundColor Green
Write-Host "Items Queued for Inspection:" -ForegroundColor White
if ($doScanEngine) {
    Write-Host "  - Base Game Engine Audit (projectzomboid.jar Deep Malware & Integrity Scan)" -ForegroundColor DarkCyan
}
if ($allJars.Count -gt 0) {
    Write-Host "  - $($allJars.Count) Mod JAR Archives" -ForegroundColor DarkCyan
}
if ($allLooseClasses.Count -gt 0) {
    Write-Host "  - $($allLooseClasses.Count) Loose Class Overrides" -ForegroundColor DarkCyan
}
if ($doScanLauncher) {
    Write-Host "  - Main Game Launcher Config (ProjectZomboid64.json)" -ForegroundColor DarkCyan
}
if ($customPath) {
    Write-Host "  - Custom Target: $customPath" -ForegroundColor DarkCyan
}
Write-Host "  - All Locations for Rogue Native Binaries (.dll, .exe, scripts)" -ForegroundColor DarkCyan

Write-Host "`nStarting $scanProfileName..." -ForegroundColor Green

$reportLines = [System.Collections.Generic.List[string]]::new()
$reportLines.Add("Project Zomboid Mod Security Scan Report - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
$reportLines.Add("Scan Profile: $scanProfileName")
$reportLines.Add("==========================================================================")

$statsCritical = 0
$statsWarning = 0

# 5. EXECUTION A: Audit Game Root Directories
if ($doScanLauncher -or $doScanEngine) {
    foreach ($gm in $targets.GameRoot) {
        Write-Host "`nAuditing Main Game Directory: $gm" -ForegroundColor DarkGray
        $reportLines.Add("Main Game Directory: $gm")

        # A.1. Launcher JSON Agent Audit
        if ($doScanLauncher) {
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

        # A.3. Base Game Engine Integrity & Malware Audit (projectzomboid.jar)
        if ($doScanEngine) {
            $engineRes = Audit-PzEngine $gm $reportLines
            if ($engineRes) {
                $statsCritical += $engineRes.Critical
                $statsWarning += $engineRes.Warnings
            }
        }
    }
}

# 6. EXECUTION B: Audit Native Binaries in Workshop & User Mod Dirs
$nonRootDirs = @()
if ($doScanWorkshop) { $nonRootDirs += $targets.Workshop }
if ($doScanUserMods) { $nonRootDirs += $targets.UserMods }
if ($customPath -and ((Get-Item $customPath) -is [System.IO.DirectoryInfo])) { $nonRootDirs += $customPath }

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

# 7. EXECUTION C: Scan JAR Packages with Fast Stream Reader
if ($allJars.Count -gt 0) {
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
                if ($entry.FullName.EndsWith(".class")) {
                    $es = $entry.Open()
                    $sr = New-Object System.IO.StreamReader($es, $encoding)
                    $content = $sr.ReadToEnd()
                    $sr.Dispose()
                    $es.Dispose()

                    foreach ($p in $tier1Patterns) {
                        if ($content.IndexOf($p, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                            if (-not (Test-IsWhitelisted $jar.FullName $entry.FullName $p)) {
                                $jarCritical += "$($entry.Name) -> contains '$p'"
                            }
                        }
                    }
                    foreach ($p in $tier2Patterns) {
                        if ($content.IndexOf($p, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                            if (-not (Test-IsWhitelisted $jar.FullName $entry.FullName $p)) {
                                $jarWarning += "$($entry.Name) -> calls '$p'"
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
}

# 8. EXECUTION D: Scan Loose .class Files with Fast Stream Reader
if ($allLooseClasses.Count -gt 0) {
    Write-Host "`nScanning $($allLooseClasses.Count) Loose Class Overrides..." -ForegroundColor DarkGray
    $looseCritical = @()
    $looseWarning = @()
    $cIdx = 0

    foreach ($cf in $allLooseClasses) {
        $cIdx++
        if ($cIdx % 50 -eq 0 -or $cIdx -eq $allLooseClasses.Count) {
            Show-ModProgressBar $cIdx $allLooseClasses.Count "Checking loose classes ($cIdx/$($allLooseClasses.Count))"
        }
        try {
            $fs = [System.IO.File]::OpenRead($cf.FullName)
            $sr = New-Object System.IO.StreamReader($fs, $encoding)
            $content = $sr.ReadToEnd()
            $sr.Dispose()
            $fs.Dispose()

            foreach ($p in $tier1Patterns) {
                if ($content.IndexOf($p, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                    if (-not (Test-IsWhitelisted $cf.FullName $cf.Name $p)) {
                        $looseCritical += "$($cf.Name) -> $p"
                    }
                }
            }
            foreach ($p in $tier2Patterns) {
                if ($content.IndexOf($p, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                    if (-not (Test-IsWhitelisted $cf.FullName $cf.Name $p)) {
                        $looseWarning += "$($cf.Name) -> $p"
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
Write-Host "Profile Executed:      $scanProfileName"
Write-Host "Workshop Locations:    $($targets.Workshop.Count)"
Write-Host "Game Root Locations:   $($targets.GameRoot.Count)"
Write-Host "User Mod Locations:    $($targets.UserMods.Count)"
if ($doScanEngine) {
    Write-Host "Base Game Engines:     $($targets.GameRoot.Count) Audited"
} else {
    Write-Host "Base Game Engines:     Skipped (Included in Full Deep Scan)"
}
Write-Host "Total Mod JARs:        $($allJars.Count) Scanned"
if ($doScanLooseClasses) {
    Write-Host "Loose Class Overrides: $($allLooseClasses.Count) Scanned"
} else {
    Write-Host "Loose Class Overrides: Skipped (Included in Full Deep Scan)"
}

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
