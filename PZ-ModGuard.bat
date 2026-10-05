<# :
@echo off
title "Project Zomboid - Java and Binary Mod Guard v2.8.0"
color 0F
set "PZMG_SELF=%~f0"
set "PZMG_PROFILE="
if /i "%~1"=="--launch" goto :launch
powershell -NoProfile -ExecutionPolicy Bypass -Command "Invoke-Expression ([System.IO.File]::ReadAllText('%PZMG_SELF%'))"
echo.
pause
exit /b

rem Steam launch option:  "C:\path\to\PZ-ModGuard.bat" --launch %command%
rem Runs a Quick Scan. Only a clean result starts the game directly; anything found (or a failed scan) waits
rem for the user to confirm, and anything but Y cancels the launch.
rem DISCLAIMER: Provided "AS IS" for heuristic security analysis. No scanner can guarantee
rem 100% threat detection against novel malware. Mod at your own risk. The authors assume no liability.
:launch
set "PZMG_PROFILE=1"
set "PZMG_GAME="
:collect
shift
if "%~1"=="" goto :scan
set PZMG_GAME=%PZMG_GAME% "%~1"
goto :collect
:scan
powershell -NoProfile -ExecutionPolicy Bypass -Command "Invoke-Expression ([System.IO.File]::ReadAllText('%PZMG_SELF%'))"
set "PZMG_RC=%ERRORLEVEL%"
if "%PZMG_RC%"=="0" goto :play
set "PZMG_MSG=The scan did not finish"
if "%PZMG_RC%"=="10" set "PZMG_MSG=Suspicious items found (see above)"
if "%PZMG_RC%"=="20" set "PZMG_MSG=CRITICAL THREATS FOUND (see above)"
echo.
choice /c YN /n /m "%PZMG_MSG%. Launch Project Zomboid anyway? [Y/N] "
if errorlevel 2 exit /b 1
:play
%PZMG_GAME%
exit /b
#>

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$encoding = [System.Text.Encoding]::GetEncoding("ISO-8859-1")

Clear-Host
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "       PROJECT ZOMBOID - ADVANCED JAVA & BINARY MOD GUARD        " -ForegroundColor Cyan
Write-Host "                        Version 2.8.0                            " -ForegroundColor DarkCyan
Write-Host "            Discord: https://discord.gg/5rmsnwMPez               " -ForegroundColor DarkGray
Write-Host "   Coded with the assistance of Google Gemini and Claude Code    " -ForegroundColor DarkGray
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " DISCLAIMER: Provided 'AS IS' for heuristic security analysis.   " -ForegroundColor DarkGray
Write-Host " No scanner guarantees 100% threat detection. Mod at your risk.  " -ForegroundColor DarkGray
Write-Host "=================================================================" -ForegroundColor Cyan

# 1. JVM Class File Constant Pool Parser (compiled once at startup by the C# compiler built into Windows)
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;
public static class PzmgClassFile {
    static int U16(byte[] b, int o) { return (b[o] << 8) | b[o + 1]; }

    // Returns null when the bytes are not a well-formed class file. Otherwise three newline-wrapped lists:
    // [0] every UTF-8 constant (names, descriptors, literals), [1] string literals only,
    // [2] every field/method reference resolved to "owner.member" (e.g. "java/lang/ProcessBuilder.start").
    public static string[] Parse(byte[] b) {
        if (b == null || b.Length < 10 || b[0] != 0xCA || b[1] != 0xFE || b[2] != 0xBA || b[3] != 0xBE) return null;
        try {
            int n = U16(b, 8), pos = 10;
            string[] utf = new string[n];
            byte[] tag = new byte[n];
            int[] x = new int[n], y = new int[n];
            for (int i = 1; i < n; i++) {
                byte t = b[pos++];
                tag[i] = t;
                switch (t) {
                    case 1: int len = U16(b, pos); utf[i] = Encoding.UTF8.GetString(b, pos + 2, len); pos += 2 + len; break;
                    case 7: case 8: case 16: case 19: case 20: x[i] = U16(b, pos); pos += 2; break;
                    case 9: case 10: case 11: case 12: case 17: case 18: x[i] = U16(b, pos); y[i] = U16(b, pos + 2); pos += 4; break;
                    case 3: case 4: pos += 4; break;
                    case 5: case 6: pos += 8; i++; break;
                    case 15: pos += 3; break;
                    default: return null;
                }
            }
            StringBuilder all = new StringBuilder("\n"), lit = new StringBuilder("\n"), refs = new StringBuilder("\n");
            for (int i = 1; i < n; i++) {
                if (tag[i] == 1) all.Append(utf[i]).Append('\n');
                else if (tag[i] == 8) lit.Append(utf[x[i]]).Append('\n');
                else if (tag[i] == 9 || tag[i] == 10 || tag[i] == 11) {
                    int cls = x[i], nat = y[i];
                    if (tag[cls] != 7 || tag[nat] != 12) return null;
                    refs.Append(utf[x[cls]]).Append('.').Append(utf[x[nat]]).Append('\n');
                }
            }
            return new string[] { all.ToString(), lit.ToString(), refs.ToString() };
        } catch (Exception) { return null; }
    }

    public static string Sha256(byte[] b) {
        using (var h = System.Security.Cryptography.SHA256.Create())
            return BitConverter.ToString(h.ComputeHash(b)).Replace("-", "").ToLowerInvariant();
    }

    // Hits are {tier, entry, pattern, text, classHash}. Tier 1: string literals; Tier 2: exact "owner.member" references and
    // whole constant-pool names (which also catch reflective calls).
    public static void ScanClass(byte[] b, string entry, string[] t1, string[] t2Refs, string[] t2Names, List<string[]> hits) {
        string[] cp = Parse(b);
        string hash = Sha256(b);
        if (cp == null) { hits.Add(new[] { "2", entry, "invalid-class", entry + " -> not a valid class file (corrupt, encrypted or disguised)", hash }); return; }
        foreach (string p in t1)
            if (cp[1].IndexOf(p, StringComparison.OrdinalIgnoreCase) >= 0) hits.Add(new[] { "1", entry, p, entry + " -> contains '" + p + "'", hash });
        foreach (string p in t2Refs)
            if (cp[2].Contains("\n" + p + "\n")) hits.Add(new[] { "2", entry, p, entry + " -> calls '" + p + "'", hash });
        foreach (string p in t2Names)
            if (cp[0].Contains("\n" + p + "\n")) hits.Add(new[] { "2", entry, p, entry + " -> references '" + p + "'", hash });
    }

    static readonly Regex Archive = new Regex(@"\.(jar|zip)$", RegexOptions.IgnoreCase);
    static readonly Regex Native = new Regex(@"\.(dll|exe|so|dylib|sys|bat|cmd|ps1|vbs)$", RegexOptions.IgnoreCase);

    // One recursive walk collecting files with any of the given extensions. Unreadable folders are skipped and
    // junctions / symlinks are not followed.
    public static string[] FindFiles(string root, string[] exts) {
        var found = new List<string>();
        var dirs = new Stack<string>();
        dirs.Push(root);
        while (dirs.Count > 0) {
            string d = dirs.Pop();
            try {
                foreach (string f in Directory.GetFiles(d))
                    foreach (string e in exts)
                        if (f.EndsWith(e, StringComparison.OrdinalIgnoreCase)) { found.Add(f); break; }
                foreach (string sub in Directory.GetDirectories(d))
                    if ((File.GetAttributes(sub) & FileAttributes.ReparsePoint) == 0) dirs.Push(sub);
            } catch (Exception) { }
        }
        return found.ToArray();
    }

    static byte[] ReadAll(ZipArchiveEntry e) {
        using (var s = e.Open()) using (var ms = new MemoryStream()) { s.CopyTo(ms); return ms.ToArray(); }
    }

    // Scans every entry of a zip/jar, recursing into nested archives and flagging embedded native binaries.
    // classHashes (optional) collects the SHA-256 of each top-level class entry.
    public static void ScanArchive(Stream stream, string prefix, string[] t1, string[] t2Refs, string[] t2Names,
                                   List<string[]> hits, List<string> classHashes) {
        using (var z = new ZipArchive(stream, ZipArchiveMode.Read)) {
            foreach (ZipArchiveEntry e in z.Entries) {
                string name = prefix + e.FullName;
                if (e.FullName.EndsWith(".class")) {
                    byte[] b = ReadAll(e);
                    if (classHashes != null) classHashes.Add(Sha256(b));
                    ScanClass(b, name, t1, t2Refs, t2Names, hits);
                } else if (Archive.IsMatch(e.FullName)) {
                    try { ScanArchive(new MemoryStream(ReadAll(e)), name + "!/", t1, t2Refs, t2Names, hits, null); }
                    catch (Exception) { hits.Add(new[] { "2", name, "nested-archive", name + " -> nested archive could not be opened", "" }); }
                } else if (Native.IsMatch(e.FullName)) {
                    byte[] nb = ReadAll(e);
                    hits.Add(new[] { "2", name, "native", name + " -> embedded native binary / script", Sha256(nb) });
                }
            }
        }
    }
}
'@ -ReferencedAssemblies ([System.IO.Compression.ZipArchive].Assembly.Location)

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
$whitelistedAgents = @("-agentlib:zbNative", "-agentlib:pz3dLoader")
$selfPath = $env:PZMG_SELF

# Trust is scoped to the Steam Workshop item a file comes from. Steam assigns these IDs, so a malicious mod
# cannot claim another mod's ID the way it can copy a folder name, file name or class name.
$wsZombieBuddy = "ws:3619862853,ws:3807686870"
$wsPZ3D        = "ws:3807334881"
$wsPzOpt       = "ws:3805285544"
$wsViewpoint   = "ws:3809306528"
$wsRichPres    = "ws:3785376350"
$wsCarPhysics  = "ws:3796880595"

# Native binaries expected inside one Workshop item (or as a byte-identical copy of it in the game folder)
$knownNativeFrameworks = @{
    "pz3dLoader.dll" = @($wsPZ3D, "PZ3D 3D Camera Engine Hook (Native C++ Binary)")
    "zbNative.dll"   = @($wsZombieBuddy, "ZombieBuddy Build 42 Native Hook Agent")
}
$knownFrameworksFound = [System.Collections.Generic.List[string]]::new()

# Install manifests ("relative/path sha256" per line) that mods write into the game folder for their class overrides
$installManifests = @{ "pzopt-installed.txt" = $wsPzOpt }

$knownDevScripts = @(
    "$wsCarPhysics|build.ps1",
    "$wsCarPhysics|test.ps1",
    "$wsPzOpt|install.ps1"
)

function Test-InScope($scope, $scopeList) {
    return ($scope -and (($scopeList -split ',') -contains $scope))
}

function Test-IsKnownDevScript($scope, $fileName) {
    foreach ($rule in $knownDevScripts) {
        $parts = $rule.Split('|')
        if ((Test-InScope $scope $parts[0]) -and $fileName -like $parts[1]) { return $true }
    }
    return $false
}

# Tier 1: matched against string literals in the class
$tier1Patterns = @(
    "discord.com/api/webhooks", "discordapp.com/api/webhooks",
    "api.telegram.org", "pastebin.com/raw", "iplogger", "grabify",
    "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe",
    "certutil", "bitsadmin", "curl.exe",
    "\AppData\Roaming\discord", "\AppData\Local\Google\Chrome", "\AppData\Roaming\Mozilla",
    "Start Menu\Programs\Startup"
)

# Tier 2: exact field/method references ("owner.member") resolved from the constant pool...
$tier2Refs = @(
    "java/net/URLClassLoader.<init>",
    "java/lang/ProcessBuilder.start", "java/lang/Runtime.exec",
    "javax/crypto/Cipher.init",
    "java/net/Socket.<init>", "java/net/ServerSocket.<init>",
    "java/net/URL.openConnection", "java/net/URL.openStream",
    "java/net/http/HttpClient.send", "java/net/http/HttpClient.sendAsync"
)
# ...plus whole constant-pool names, which also catch these being called through reflection
$tier2Names = @("defineClass", "defineHiddenClass", "java.lang.ProcessBuilder", "java.lang.Runtime")

# "Scope|EntryPathPattern|PatternPattern". A rule whose last field is "*" never hides a Tier 1 hit.
$scopedWhitelist = @(
    # Base game: bundled Javacord library contains the Discord webhook API URL
    "engine|org/javacord/*|discord.com/api/webhooks",

    # ZombieBuddy: Java mod loader. Bundled ByteBuddy / ClassGraph / BouncyCastle library code
    "$wsZombieBuddy|net/bytebuddy/*|*",
    "$wsZombieBuddy|io/github/classgraph/*|*",
    "$wsZombieBuddy|nonapi/io/github/classgraph/*|*",
    "$wsZombieBuddy|zb/org/bouncycastle/*|*",
    "$wsZombieBuddy|win32-x86*/attach_hotspot_windows.dll|native",
    # ZombieBuddy itself: mod-approval window (subprocess), mod-author lookups (Steam API, GitHub)
    "$wsZombieBuddy|me/zed_0xff/zombie_buddy/frontend/SwingModApprovalFrontend.class|java/lang/ProcessBuilder.start",
    "$wsZombieBuddy|me/zed_0xff/zombie_buddy/*|java/net/http/HttpClient.send*",
    "$wsZombieBuddy|me/zed_0xff/zombie_buddy/PatchTransformer.class|defineClass",

    # Viewpoint: reads GPU utilization through Windows typeperf
    "$wsViewpoint|viewpoint/platform/GpuBusy.class|java/lang/ProcessBuilder.start",

    # Discord Rich Presence: local IPC socket to the Discord desktop app
    "$wsRichPres|*LinuxIPC*|java/net/Socket.<init>",
    "$wsRichPres|*IPCClient*|java/net/Socket.<init>",

    # PZ3D: compatibility check, self-updater, bundled ByteBuddy
    "$wsPZ3D|*CompatibilityCheck*|java/net/URLClassLoader.<init>",
    "$wsPZ3D|*SelfUpdater*|java/lang/ProcessBuilder.start",
    "$wsPZ3D|*AgentBuilder*|java/net/URLClassLoader.<init>",
    "$wsPZ3D|*ClassFileLocator*|java/net/URLClassLoader.<init>",
    "$wsPZ3D|*net/bytebuddy/*|*",

    # PZ_Optimization: restart / uninstall helpers run hidden PowerShell, sound probe, updater (its GitHub
    # releases), override loader (reads its own jar resources), copies of stock classes that already exec
    "$wsPzOpt|*pzopt/Restart.class|powershell.exe",
    "$wsPzOpt|*pzopt/Uninstall.class|powershell.exe",
    "$wsPzOpt|*pzopt/Restart.class|java/lang/ProcessBuilder.start",
    "$wsPzOpt|*pzopt/Uninstall.class|java/lang/ProcessBuilder.start",
    "$wsPzOpt|*pzopt/SoundProbe.class|java/lang/ProcessBuilder.start",
    "$wsPzOpt|*zombie/GameWindow.class|java/lang/ProcessBuilder.start",
    "$wsPzOpt|*pzopt/Updater.class|java/net/http/HttpClient.send*",
    "$wsPzOpt|*pzopt/UpdateDelta*.class|java/net/http/HttpClient.send*",
    "$wsPzOpt|*pzopt/Overrides.class|java/net/URL.openStream",
    "$wsPzOpt|*gameStates/MainScreenState.class|java/lang/Runtime.exec"
)

function Test-IsWhitelisted($scope, $entryPath, $pattern, [switch]$Tier1) {
    foreach ($rule in $scopedWhitelist) {
        $parts = $rule.Split('|')
        if ($Tier1 -and $parts[2] -eq '*') { continue }
        if ((Test-InScope $scope $parts[0]) -and $entryPath -like $parts[1] -and $pattern -like $parts[2]) { return $true }
    }
    return $false
}

$stockPzPackages = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
@(
    "astar", "com", "de", "fmod", "generation", "gnu", "imgui", "io",
    "jassimp", "javax", "kotlin", "META-INF", "N3D", "okhttp3", "okio",
    "org", "oshi", "pl", "se", "windows", "macos", "linux", "zombie"
) | ForEach-Object { [void]$stockPzPackages.Add($_) }

# 4.1. Scopes: "ws:<WorkshopID>" for files inside a Workshop item, "engine" for projectzomboid.jar, otherwise
# inherited from a byte-identical Workshop file or a verified install-manifest entry. Unscoped files get no whitelist.
$workshopHashes = @{}   # sha256 -> scope of jars / native binaries inside Workshop items
$manifestFiles = @{}    # full path (lowercase) -> @(sha256, scope) from install manifests
$manifestHashes = @{}   # sha256 -> scope, for recognizing manifest files repackaged into a jar

function Get-WorkshopScope($path) {
    $m = [regex]::Match($path, '\\workshop\\content\\108600\\(\d+)\\')
    if ($m.Success) { return "ws:$($m.Groups[1].Value)" }
    return ""
}

function Get-FileScope($path) {
    $s = Get-WorkshopScope $path
    if ($s) { return $s }
    $h = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLower()
    if ($workshopHashes.ContainsKey($h)) { return $workshopHashes[$h] }
    return ""
}

# 4.2. User Exceptions (Cryptographically Verified SHA-256 Custom Exceptions)
function Get-ExceptionsFilePath() {
    $scriptDir = if ($selfPath) { Split-Path $selfPath } else { (Get-Location).Path }
    $portablePath = Join-Path $scriptDir "pzmg_exceptions.json"
    if (Test-Path -LiteralPath $portablePath) { return $portablePath }
    $localDir = Join-Path $env:LOCALAPPDATA "PZ-ModGuard"
    if (-not (Test-Path -LiteralPath $localDir)) { [void](New-Item -ItemType Directory -Path $localDir -Force) }
    return (Join-Path $localDir "pzmg_exceptions.json")
}

$userExceptions = [System.Collections.Generic.List[object]]::new()
$userExceptionsLoadedCount = 0
$statsUserExceptions = 0
$promptWarnings = [System.Collections.Generic.List[object]]::new()

function Load-UserExceptions() {
    $script:userExceptions.Clear()
    $candidateFiles = @()
    $localPath = Join-Path $env:LOCALAPPDATA "PZ-ModGuard\pzmg_exceptions.json"
    if (Test-Path -LiteralPath $localPath) { $candidateFiles += $localPath }
    $scriptDir = if ($selfPath) { Split-Path $selfPath } else { (Get-Location).Path }
    $portablePath = Join-Path $scriptDir "pzmg_exceptions.json"
    if ((Test-Path -LiteralPath $portablePath) -and $portablePath -ne $localPath) { $candidateFiles += $portablePath }

    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($f in $candidateFiles) {
        try {
            $content = [System.IO.File]::ReadAllText($f)
            $items = ConvertFrom-Json $content
            if ($items -is [System.Array] -or $items -is [System.Collections.IEnumerable]) {
                foreach ($it in $items) {
                    $key = "$($it.sha256)|$($it.entry)|$($it.pattern)"
                    if (-not $seen.Contains($key)) {
                        [void]$seen.Add($key)
                        $script:userExceptions.Add($it)
                    }
                }
            } elseif ($items) {
                $key = "$($items.sha256)|$($items.entry)|$($items.pattern)"
                if (-not $seen.Contains($key)) {
                    [void]$seen.Add($key)
                    $script:userExceptions.Add($items)
                }
            }
        } catch {}
    }
    $script:userExceptionsLoadedCount = $script:userExceptions.Count
}

Load-UserExceptions

function Save-UserExceptions() {
    $targetPath = Get-ExceptionsFilePath
    $dir = Split-Path $targetPath
    if (-not (Test-Path -LiteralPath $dir)) { [void](New-Item -ItemType Directory -Path $dir -Force) }
    $json = ConvertTo-Json -InputObject @($script:userExceptions) -Depth 4
    [System.IO.File]::WriteAllText($targetPath, $json, [System.Text.Encoding]::UTF8)
}

function Test-IsUserException($fileHash, $classHash, $entryPath, $pattern, $tier, $fileName) {
    foreach ($ex in $script:userExceptions) {
        $exHash = "$($ex.sha256)".Trim().ToLower()
        if (-not $exHash) { continue }

        # Hash must match either the container file hash or the specific class bytecode hash
        $hashMatch = ($fileHash -and $fileHash.ToLower() -eq $exHash) -or ($classHash -and $classHash.ToLower() -eq $exHash)
        if (-not $hashMatch) { continue }

        # Tier 1 Critical Protection: wildcard '*' pattern is NOT permitted for Tier 1
        if ($tier -eq 1 -and ($ex.pattern -eq '*' -or -not $ex.pattern)) { continue }

        # Target entry or file name match
        $entryMatch = (-not $ex.entry -or $ex.entry -eq '*' -or $entryPath -like $ex.entry -or ($fileName -and $fileName -like $ex.entry) -or ($fileName -and $fileName -like $ex.target))
        $patternMatch = (-not $ex.pattern -or $ex.pattern -eq '*' -or $pattern -like $ex.pattern)

        if ($entryMatch -and $patternMatch) {
            return $ex
        }
    }
    return $null
}

function Get-ExpiredExceptionNotice($fileHash, $classHash, $fileName, $entryPath) {
    foreach ($ex in $script:userExceptions) {
        $exTarget = "$($ex.target)".Trim()
        $exEntry = "$($ex.entry)".Trim()
        $nameMatch = ($fileName -and $fileName -like $exTarget) -or ($entryPath -and $entryPath -like $exEntry)
        if ($nameMatch) {
            $exHash = "$($ex.sha256)".Trim().ToLower()
            $matched = ($fileHash -and $fileHash.ToLower() -eq $exHash) -or ($classHash -and $classHash.ToLower() -eq $exHash)
            if (-not $matched) {
                $hashShort = if ($ex.sha256.Length -ge 10) { $ex.sha256.Substring(0,10) + "..." } else { $ex.sha256 }
                return "Stored exception for '$exTarget' expired because the file changed (stored SHA-256: $hashShort)"
            }
        }
    }
    return $null
}

function New-Hit($tier, $entry, $pattern, $text, $hash) {
    [PSCustomObject]@{ Tier = $tier; Entry = $entry; Pattern = $pattern; Text = $text; Hash = $hash }
}

# Hits are recorded unfiltered; whitelisting is applied later, once the owning file's scope is known.
function Add-RawHits($hits, $raw) {
    foreach ($h in $raw) {
        $hHash = if ($h.Length -gt 4) { $h[4] } else { "" }
        $hits.Add((New-Hit ([int]$h[0]) $h[1] $h[2] $h[3] $hHash))
    }
}

function Add-ClassHits($hits, [byte[]]$bytes, $entryName) {
    $raw = [System.Collections.Generic.List[string[]]]::new()
    [PzmgClassFile]::ScanClass($bytes, $entryName, $tier1Patterns, $tier2Refs, $tier2Names, $raw)
    Add-RawHits $hits $raw
}

# Scans a jar on disk (nested archives and embedded natives included). $classHashes (optional) collects class SHA-256s.
function Add-JarHits($hits, $path, $classHashes) {
    $raw = [System.Collections.Generic.List[string[]]]::new()
    $fs = [System.IO.File]::OpenRead($path)
    try { [PzmgClassFile]::ScanArchive($fs, "", $tier1Patterns, $tier2Refs, $tier2Names, $raw, $classHashes) }
    finally { $fs.Dispose() }
    Add-RawHits $hits $raw
}

function Select-UnlistedHits($hits, $scope, $fileHash = "", $fileName = "") {
    $critical = [System.Collections.Generic.List[object]]::new()
    $warning = [System.Collections.Generic.List[object]]::new()
    $userEx = [System.Collections.Generic.List[object]]::new()
    foreach ($h in $hits) {
        if (Test-IsWhitelisted $scope $h.Entry $h.Pattern -Tier1:($h.Tier -eq 1)) { continue }
        $ex = Test-IsUserException $fileHash $h.Hash $h.Entry $h.Pattern $h.Tier $fileName
        if ($ex) {
            $userEx.Add([PSCustomObject]@{ Hit = $h; Exception = $ex })
            continue
        }
        if ($h.Tier -eq 1) { $critical.Add($h) } else { $warning.Add($h) }
    }
    return [PSCustomObject]@{ Critical = $critical; Warning = $warning; UserExceptions = $userEx }
}

# Loads install manifests from a game folder. Returns the paths of manifest entries that are missing on disk.
function Read-InstallManifests($gm) {
    $missing = [System.Collections.Generic.List[string]]::new()
    foreach ($name in $installManifests.Keys) {
        $mf = Join-Path $gm $name
        if (-not (Test-Path -LiteralPath $mf)) { continue }
        foreach ($line in [System.IO.File]::ReadAllLines($mf)) {
            if (-not $line -or $line.StartsWith('#')) { continue }
            $rel, $sha = $line -split ' ', 2
            $full = Join-Path $gm ($rel -replace '/', '\')
            if (-not (Test-Path -LiteralPath $full)) { $missing.Add($full); continue }
            $manifestFiles[$full.ToLower()] = @($sha.Trim().ToLower(), $installManifests[$name])
            $manifestHashes[$sha.Trim().ToLower()] = $installManifests[$name]
        }
    }
    return ,$missing
}

function Audit-PzEngine($gm, $reportLines) {
    $pzJarPath = "$gm\projectzomboid.jar"
    if (-not (Test-Path -LiteralPath $pzJarPath)) {
        return $null
    }

    Write-Host "`nAuditing Base Game Engine (projectzomboid.jar)..." -ForegroundColor Cyan
    $reportLines.Add("Base Game Engine Audit: $pzJarPath")

    $pzNonStockPackages = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $hits = [System.Collections.Generic.List[object]]::new()
    $total = 0

    try {
        $zip = [System.IO.Compression.ZipFile]::OpenRead($pzJarPath)
        foreach ($entry in $zip.Entries) {
            if ($entry.FullName.EndsWith(".class")) {
                $total++
                $parts = $entry.FullName.Split('/')
                if (-not $stockPzPackages.Contains($parts[0])) {
                    $pkg = if ($parts.Length -gt 2) { "$($parts[0]).$($parts[1])" } else { $parts[0] }
                    [void]$pzNonStockPackages.Add($pkg)
                }
            }
        }
        $zip.Dispose()
        Add-JarHits $hits $pzJarPath $null
    } catch {
        Clear-ModProgressBar
        Write-Host "  [?] Notice: Could not read projectzomboid.jar (file locked or in use)." -ForegroundColor Yellow
        return $null
    }

    $pzHash = try { (Get-FileHash -LiteralPath $pzJarPath -Algorithm SHA256).Hash.ToLower() } catch { "" }
    $res = Select-UnlistedHits $hits "engine" $pzHash "projectzomboid.jar"
    if ($res.UserExceptions -and $res.UserExceptions.Count -gt 0) {
        $script:statsUserExceptions += $res.UserExceptions.Count
        foreach ($ue in $res.UserExceptions) {
            $h = $ue.Hit
            Write-Host "    [USER EXCEPTION] $($h.Entry) -> $($h.Pattern) (SHA-256 verified)" -ForegroundColor DarkCyan
            $reportLines.Add("    [USER EXCEPTION] $($pzJarPath) ($($h.Entry) -> $($h.Pattern) [SHA-256 verified])")
        }
    }
    $pzCritical = @($res.Critical | ForEach-Object { "$($_.Entry) -> contains '$($_.Pattern)'" })
    # Tier 2 only matters for classes injected by mods: stock engine code legitimately uses these APIs
    $pzInjectedWarnings = @($res.Warning | Where-Object { -not $stockPzPackages.Contains($_.Entry.Split('/')[0]) } |
        ForEach-Object { "$($_.Entry) -> $($_.Pattern)" })

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

# 3.7. Auto-Scan Setup: writes Project Zomboid's Steam Launch Options so every launch runs a Quick Scan first.
# Steam keeps them per account in userdata\<id>\config\localconfig.vdf (apps > 108600 > LaunchOptions) and
# rewrites that file when it exits, so Steam must be closed while it is edited.
$ourLaunchPrefixRe = '"[^"]*(PZ-ModGuard\.bat|pz-modguard\.sh)" --launch '

# Adds (or with $prefix = $null removes) "<script>" --launch in front of %command%, keeping the user's own options
function Get-NewLaunchOptions($current, $prefix) {
    $opts = [regex]::Replace($current, $ourLaunchPrefixRe, '', 'IgnoreCase')
    if (-not $prefix) { if ($opts.Trim() -eq '%command%') { return '' } else { return $opts } }
    $i = $opts.IndexOf('%command%')
    if ($i -ge 0) { return $opts.Substring(0, $i) + "$prefix " + $opts.Substring($i) }
    return "$prefix %command% $opts".TrimEnd()
}

function Set-SteamLaunchOptions($vdfPath, $prefix) {
    $text = [System.IO.File]::ReadAllText($vdfPath)
    $appPath = 'userlocalconfigstore/software/valve/steam/apps/108600'
    $stack = [System.Collections.Generic.List[string]]::new()
    $key = $null; $appOpen = -1; $value = $null
    foreach ($m in [regex]::Matches($text, '"((?:[^"\\]|\\.)*)"|[{}]|//[^\n]*')) {
        $t = $m.Value
        if ($t.StartsWith('//')) { continue }
        if ($t -eq '{') {
            $stack.Add("$key".ToLower()); $key = $null
            if (($stack -join '/') -eq $appPath) { $appOpen = $m.Index + 1 }
        } elseif ($t -eq '}') {
            if ($stack.Count -gt 0) { $stack.RemoveAt($stack.Count - 1) }
        } elseif ($null -eq $key) {
            $key = $m.Groups[1].Value
        } else {
            if (($stack -join '/') -eq $appPath -and $key -eq 'LaunchOptions') { $value = $m }
            $key = $null
        }
    }
    if ($appOpen -lt 0) { return "skipped (Project Zomboid has not been played on this account)" }
    $current = if ($value) { [regex]::Replace($value.Groups[1].Value, '\\(.)', '$1') } else { '' }
    $new = Get-NewLaunchOptions $current $prefix
    if ($new -eq $current) { return "already up to date" }
    $quoted = '"' + $new.Replace('\', '\\').Replace('"', '\"') + '"'
    if ($value) { $text = $text.Remove($value.Index, $value.Length).Insert($value.Index, $quoted) }
    else { $text = $text.Insert($appOpen, "`n`t`t`t`t`t`t`"LaunchOptions`"`t`t$quoted") }
    Copy-Item -LiteralPath $vdfPath "$vdfPath.pzmg-backup" -Force
    [System.IO.File]::WriteAllText($vdfPath, $text, (New-Object System.Text.UTF8Encoding $false))
    if ($new) { return "Launch Options set to: $new" } else { return "Launch Options cleared" }
}

function Install-AutoScan([switch]$Remove) {
    if (-not $steamPath -or -not (Test-Path -LiteralPath "$steamPath\userdata")) {
        Write-Host "`n[!] Steam was not found, so the Launch Options cannot be set automatically." -ForegroundColor Red
        return
    }
    if (Get-Process steam -ErrorAction SilentlyContinue) {
        Write-Host "`nSteam is running. It overwrites its settings when it exits, so it has to be closed first." -ForegroundColor Yellow
        if ((Read-Host "Close Steam now? [Y/N]") -notmatch '^[Yy]') { Write-Host "Cancelled. Nothing was changed."; return }
        Start-Process "$steamPath\steam.exe" -ArgumentList "-shutdown"
        for ($i = 0; $i -lt 60 -and (Get-Process steam -ErrorAction SilentlyContinue); $i++) { Start-Sleep -Seconds 1 }
        if (Get-Process steam -ErrorAction SilentlyContinue) {
            Write-Host "[!] Steam is still running. Close it, then choose this option again. Nothing was changed." -ForegroundColor Red
            return
        }
    }
    $prefix = $null
    if (-not $Remove) {
        # A fixed copy, so the Launch Options keep working after the downloaded file is moved or deleted
        $dir = Join-Path $env:LOCALAPPDATA "PZ-ModGuard"
        $dest = Join-Path $dir "PZ-ModGuard.bat"
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        if ($selfPath -and $selfPath -ne $dest) { Copy-Item -LiteralPath $selfPath $dest -Force }
        $prefix = "`"$dest`" --launch"
        Write-Host "`nInstalled scanner: $dest" -ForegroundColor Green
    }
    foreach ($vdf in Get-ChildItem -Path "$steamPath\userdata\*\config\localconfig.vdf" -ErrorAction SilentlyContinue) {
        $account = $vdf.Directory.Parent.Name
        try { Write-Host "  Steam account ${account}: $(Set-SteamLaunchOptions $vdf.FullName $prefix)" }
        catch { Write-Host "  Steam account ${account}: failed ($_)" -ForegroundColor Red }
    }
    if ($Remove) {
        Write-Host "`nAuto-Scan removed. You can delete $env:LOCALAPPDATA\PZ-ModGuard." -ForegroundColor Green
    } else {
        Write-Host "`nDone. Start Steam: every Project Zomboid launch now runs a Quick Scan first." -ForegroundColor Green
        Write-Host "A backup of each changed file was saved as localconfig.vdf.pzmg-backup." -ForegroundColor DarkGray
    }
}

function Show-ExceptionsMenu() {
    while ($true) {
        Clear-Host
        $exFile = Get-ExceptionsFilePath
        Write-Host "=================================================================" -ForegroundColor Cyan
        Write-Host "                    USER SHA-256 EXCEPTIONS                      " -ForegroundColor Cyan
        Write-Host "=================================================================" -ForegroundColor Cyan
        Write-Host "Config File: $exFile" -ForegroundColor DarkGray
        Write-Host "Active Exceptions: $($script:userExceptions.Count)" -ForegroundColor White
        Write-Host ""
        Write-Host "  [1] List All Active Exceptions" -ForegroundColor White
        Write-Host "  [2] Add Exception Manually (File Drag-and-Drop or Path)" -ForegroundColor White
        Write-Host "  [3] Remove an Exception" -ForegroundColor White
        Write-Host "  [4] Open Exceptions File in Notepad" -ForegroundColor White
        Write-Host "  [5] Clear All Exceptions" -ForegroundColor White
        Write-Host "  [B] Back to Main Menu" -ForegroundColor DarkGray
        Write-Host "=================================================================" -ForegroundColor Cyan
        Write-Host ""
        $exChoice = Read-Host "Select option [1-5, B]"
        switch ($exChoice) {
            "1" {
                Write-Host ""
                if ($script:userExceptions.Count -eq 0) {
                    Write-Host "  No user exceptions defined yet." -ForegroundColor Yellow
                } else {
                    $idx = 0
                    foreach ($e in $script:userExceptions) {
                        $idx++
                        Write-Host "  [$idx] Target: $($e.target) | Entry: $($e.entry) | Pattern: $($e.pattern)" -ForegroundColor Cyan
                        Write-Host "      SHA-256: $($e.sha256)" -ForegroundColor DarkGray
                        if ($e.comment) { Write-Host "      Note:    $($e.comment)" -ForegroundColor Gray }
                    }
                }
                Write-Host ""
                pause
            }
            "2" {
                Write-Host ""
                $p = Read-Host "Enter or drag-and-drop the file to exempt (.jar, .class, .dll, etc.)"
                $p = $p.Trim().Trim('"').Trim("'")
                if (-not (Test-Path -LiteralPath $p)) {
                    Write-Host "`n[!] File not found: $p" -ForegroundColor Red
                    Start-Sleep -Seconds 2
                    continue
                }
                $leaf = Split-Path $p -Leaf
                $hash = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLower()
                Write-Host "  File:    $leaf" -ForegroundColor Cyan
                Write-Host "  SHA-256: $hash" -ForegroundColor DarkGray
                $ent = Read-Host "Enter class entry to exempt (or press [ENTER] for entire file '*')"
                if ([string]::IsNullOrWhiteSpace($ent)) { $ent = "*" }
                $pat = Read-Host "Enter API pattern to exempt (or press [ENTER] for all warnings '*')"
                if ([string]::IsNullOrWhiteSpace($pat)) { $pat = "*" }
                $note = Read-Host "Enter optional note/comment (e.g. '$leaf LLM mod')"
                
                $newEx = [PSCustomObject]@{
                    sha256 = $hash
                    target = $leaf
                    entry = $ent
                    pattern = $pat
                    comment = $note
                    date_added = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                }
                $script:userExceptions.Add($newEx)
                Save-UserExceptions
                Write-Host "`n[+] Exception added successfully!" -ForegroundColor Green
                Start-Sleep -Seconds 2
            }
            "3" {
                Write-Host ""
                if ($script:userExceptions.Count -eq 0) {
                    Write-Host "  No exceptions to remove." -ForegroundColor Yellow
                    Start-Sleep -Seconds 2
                    continue
                }
                $idx = 0
                foreach ($e in $script:userExceptions) {
                    $idx++
                    Write-Host "  [$idx] $($e.target) ($($e.entry) -> $($e.pattern))" -ForegroundColor White
                }
                $rem = Read-Host "`nEnter item number to remove (or [C] to cancel)"
                if ($rem -match '^\d+$' -and [int]$rem -ge 1 -and [int]$rem -le $script:userExceptions.Count) {
                    $removed = $script:userExceptions[[int]$rem - 1]
                    $script:userExceptions.RemoveAt([int]$rem - 1)
                    Save-UserExceptions
                    Write-Host "`n[-] Removed exception for $($removed.target)." -ForegroundColor Yellow
                    Start-Sleep -Seconds 2
                }
            }
            "4" {
                $targetFile = Get-ExceptionsFilePath
                if (-not (Test-Path -LiteralPath $targetFile)) { Save-UserExceptions }
                Start-Process "notepad.exe" $targetFile
            }
            "5" {
                $confirm = Read-Host "Are you sure you want to clear ALL exceptions? [Y/N]"
                if ($confirm -match '^[Yy]') {
                    $script:userExceptions.Clear()
                    Save-UserExceptions
                    Write-Host "`n[!] All exceptions cleared." -ForegroundColor Yellow
                    Start-Sleep -Seconds 2
                }
            }
            default {
                # Return to caller
            }
        }
    }
}

# USER SCAN PROFILE SELECTION (preset by the batch header when launched from Steam with --launch)
if ($env:PZMG_PROFILE) {
    $prompt = $env:PZMG_PROFILE
} else {
    while ($true) {
        Write-Host "`n=================================================================" -ForegroundColor Cyan
        Write-Host "                      SELECT SCAN PROFILE                        " -ForegroundColor Cyan
        Write-Host "=================================================================" -ForegroundColor Cyan
        Write-Host "  [1] Quick Scan      - Workshop & User Mods (Fastest, ~1.5s) [DEFAULT]" -ForegroundColor White
        Write-Host "  [2] Full Deep Scan  - Complete Audit (Base Engine + Workshop + Overrides)" -ForegroundColor White
        Write-Host "  [3] Base Engine     - projectzomboid.jar Integrity & Security Audit" -ForegroundColor White
        Write-Host "  [4] Custom Target   - Scan a specific Mod Folder or .JAR file" -ForegroundColor White
        Write-Host "  [5] Custom Game Dir - Point to a GOG / Standalone / Custom PZ Folder" -ForegroundColor White
        Write-Host "  [6] Auto-Scan Setup - Scan automatically every time Project Zomboid starts (Steam)" -ForegroundColor White
        Write-Host "  [7] Remove Auto-Scan" -ForegroundColor White
        Write-Host "  [8] User Exceptions - Manage trusted SHA-256 exceptions ($($script:userExceptions.Count) Active)" -ForegroundColor White
        Write-Host "  [Q] Quit / Cancel" -ForegroundColor DarkGray
        Write-Host "=================================================================" -ForegroundColor Cyan
        Write-Host ""
        $prompt = Read-Host "Press [ENTER] for Quick Scan [1], or enter [1-8, Q]"
        if ($prompt -eq "6") { Install-AutoScan; pause; continue }
        if ($prompt -eq "7") { Install-AutoScan -Remove; pause; continue }
        if ($prompt -eq "8") { Show-ExceptionsMenu; continue }
        if ($prompt -match "^[Qq]") {
            Write-Host "`nScan cancelled by user." -ForegroundColor Yellow
            return
        }
        break
    }
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
# Loose classes in a game folder sit on the classpath ahead of projectzomboid.jar ("." comes first), so they
# replace engine code at launch. They are scanned in every profile that audits the game folder.
$gameRootClasses = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
$modNatives = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
$doScanGameRoot = ($doScanLauncher -or $doScanEngine)

$nativeExts = @(".exe", ".dll", ".vbs", ".bat", ".cmd", ".ps1")
$scanExts = @(".jar", ".class", ".so") + $nativeExts

function Test-IsUnderUserMods($path) {
    foreach ($um in $targets.UserMods) {
        if ($path.StartsWith("$um\", [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

# Sorts one folder walk into jars, loose classes and native binaries / scripts
function Add-ModFiles($root, $collectJars, $collectClasses, $collectNatives) {
    foreach ($path in [PzmgClassFile]::FindFiles($root, $scanExts)) {
        $f = [System.IO.FileInfo]$path
        if ($f.Extension -eq ".jar") { if ($collectJars) { $allJars.Add($f) } }
        elseif ($f.Extension -eq ".class") { if ($collectClasses) { $allLooseClasses.Add($f) } }
        elseif ($collectNatives -and $nativeExts -contains $f.Extension -and $f.FullName -ne $selfPath) { $modNatives.Add($f) }
        # Jars / native binaries inside Workshop items: byte-identical copies in a game folder inherit their scope
        if ($doScanGameRoot -and $f.Extension -in ".jar", ".dll", ".so" -and (Get-WorkshopScope $f.FullName)) {
            $workshopHashes[(Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLower()] = Get-WorkshopScope $f.FullName
        }
    }
}

if ($customPath) {
    if ((Get-Item $customPath) -is [System.IO.FileInfo]) {
        if ($customPath.EndsWith(".jar", [System.StringComparison]::OrdinalIgnoreCase)) {
            $allJars.Add((Get-Item $customPath))
        } elseif ($customPath.EndsWith(".class", [System.StringComparison]::OrdinalIgnoreCase)) {
            $allLooseClasses.Add((Get-Item $customPath))
        }
    } else {
        Add-ModFiles $customPath $true $true $true
    }
} else {
    foreach ($ws in $targets.Workshop) {
        if ($doScanWorkshop -or $doScanGameRoot) { Add-ModFiles $ws $doScanWorkshop ($doScanWorkshop -and $doScanLooseClasses) $doScanWorkshop }
    }
    if ($doScanUserMods) {
        foreach ($um in $targets.UserMods) { Add-ModFiles $um $true $doScanLooseClasses $true }
    }
    if ($doScanGameRoot) {
        foreach ($gm in $targets.GameRoot) {
            foreach ($path in [PzmgClassFile]::FindFiles($gm, @(".jar", ".class"))) {
                $f = [System.IO.FileInfo]$path
                if ($f.FullName -match '\\jre64\\' -or (Test-IsUnderUserMods $f.FullName) -or
                    ($f.DirectoryName -eq $gm -and $stockPzJars -contains $f.Name)) { continue }
                if ($f.Extension -eq ".jar") { $allJars.Add($f) } else { $gameRootClasses.Add($f) }
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
if ($gameRootClasses.Count -gt 0) {
    Write-Host "  - $($gameRootClasses.Count) Game Folder Code Overrides (loaded ahead of projectzomboid.jar)" -ForegroundColor DarkCyan
}
if ($allLooseClasses.Count -gt 0) {
    Write-Host "  - $($allLooseClasses.Count) Loose Class Overrides" -ForegroundColor DarkCyan
}
if ($doScanLauncher) {
    Write-Host "  - Game Launcher Config (ProjectZomboid64.json, launcher .bat files, Java environment variables)" -ForegroundColor DarkCyan
}
if ($customPath) {
    Write-Host "  - Custom Target: $customPath" -ForegroundColor DarkCyan
}
Write-Host "  - All Locations for Rogue Native Binaries (.dll, .exe, scripts)" -ForegroundColor DarkCyan

Write-Host "`nStarting $scanProfileName..." -ForegroundColor Green

$reportLines = [System.Collections.Generic.List[string]]::new()
$reportLines.Add("Project Zomboid Mod Security Scan Report - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
$reportLines.Add("Scan Profile: $scanProfileName")
$reportLines.Add("DISCLAIMER: Provided 'AS IS' without warranty of any kind. No scanner can guarantee")
$reportLines.Add("100% threat detection. The authors assume no liability for damages or data loss.")
$reportLines.Add("==========================================================================")

$statsCritical = 0
$statsWarning = 0
$statsUserExceptions = 0
$promptWarnings = [System.Collections.Generic.List[object]]::new()

function Write-Finding($severity, $msg) {
    if ($severity -eq "critical") { $script:statsCritical++; $color = "Red" }
    elseif ($severity -eq "warning") { $script:statsWarning++; $color = "Yellow" }
    else { $color = "Cyan" }
    Write-Host "  $msg" -ForegroundColor $color
    $reportLines.Add("  $msg")
}

# JVM options that load code before the game starts: agents run with full control over the JVM
function Test-JvmOptions($text, $source) {
    foreach ($m in [regex]::Matches($text, '-(agentlib|agentpath|javaagent):[^\s"]+')) {
        if ($whitelistedAgents -notcontains $m.Value) {
            Write-Finding "critical" "[CRITICAL] Unauthorized JVM Agent in ${source}: $($m.Value)"
        }
    }
    foreach ($m in [regex]::Matches($text, '-Xbootclasspath[^\s"]*')) {
        Write-Finding "critical" "[CRITICAL] Boot classpath override in ${source}: $($m.Value)"
    }
}

function Test-NativeBinary($n, $scope, $where) {
    if ($knownNativeFrameworks.ContainsKey($n.Name)) {
        $expected, $desc = $knownNativeFrameworks[$n.Name]
        if (Test-InScope $scope $expected) {
            if (-not $knownFrameworksFound.Contains($n.Name)) { $knownFrameworksFound.Add($n.Name) }
            Write-Host "  [KNOWN NATIVE FRAMEWORK] $($n.Name) ($desc)" -ForegroundColor Cyan
            $reportLines.Add("  [KNOWN NATIVE FRAMEWORK] $($n.FullName) - $desc")
        } else {
            Write-Finding "critical" "[CRITICAL] $($n.Name) is named like $desc but does not match its Workshop copy: $($n.FullName)"
        }
    } elseif (Test-IsKnownDevScript $scope $n.Name) {
        Write-Host "  [i] Notice: Non-executing dev/install script: $($n.Name)" -ForegroundColor DarkGray
        $reportLines.Add("  [i] Notice: Non-executing dev/install script: $($n.FullName)")
    } elseif (-not (Test-IsWhitelisted $scope $n.Name "native")) {
        $nHash = try { (Get-FileHash -LiteralPath $n.FullName -Algorithm SHA256).Hash.ToLower() } catch { "" }
        $ex = Test-IsUserException $nHash "" $n.Name "native" 1 $n.Name
        if ($ex) {
            $script:statsUserExceptions++
            Write-Host "  [USER EXCEPTION - CRITICAL CAPABILITY] $($n.Name) (SHA-256 verified)" -ForegroundColor DarkCyan
            $reportLines.Add("  [USER EXCEPTION - CRITICAL CAPABILITY] $($n.FullName) (SHA-256 verified)")
            return
        }
        $expNotice = Get-ExpiredExceptionNotice $nHash "" $n.Name $n.Name
        if ($expNotice) {
            Write-Finding "warning" "[!] $expNotice"
        }
        Write-Finding "critical" "[CRITICAL] Unauthorized Native Binary${where}: $($n.FullName)"
    }
}

# 5. EXECUTION A: Audit Game Root Directories
if ($doScanGameRoot) {
    foreach ($gm in $targets.GameRoot) {
        Write-Host "`nAuditing Main Game Directory: $gm" -ForegroundColor DarkGray
        $reportLines.Add("Main Game Directory: $gm")

        # A.1. Launcher Audit: JSON config, launcher scripts
        if ($doScanLauncher) {
            $jsonPath = "$gm\ProjectZomboid64.json"
            if (Test-Path -LiteralPath $jsonPath) {
                try {
                    $cfg = Get-Content -LiteralPath $jsonPath -Raw | ConvertFrom-Json
                    if ($cfg.vmArgs) { Test-JvmOptions ($cfg.vmArgs -join ' ') "ProjectZomboid64.json" }
                    foreach ($cp in @($cfg.classpath)) {
                        if ($cp -and $cp -ne "." -and $stockPzJars -notcontains $cp) {
                            Write-Finding "info" "[i] Notice: Launcher classpath includes '$cp' (scanned below)"
                        }
                    }
                } catch {}
            }
            foreach ($s in $stockPzScripts) {
                $sp = Join-Path $gm $s
                if (Test-Path -LiteralPath $sp) { Test-JvmOptions (Get-Content -LiteralPath $sp -Raw) $s }
            }
        }

        # A.2. Audit Native Binaries in Game Root
        $natives = Get-ChildItem -Path "$gm\*" -Include *.dll, *.exe, *.bat, *.cmd, *.ps1, *.vbs -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -ne $selfPath }
        foreach ($n in $natives) {
            $isStock = ($stockPzDlls -contains $n.Name -or $stockPzScripts -contains $n.Name -or $n.Name -like "ProjectZomboid*.exe")
            if (-not $isStock) { Test-NativeBinary $n (Get-FileScope $n.FullName) " in Game Root" }
        }

        # A.3. Install manifests: class overrides a mod copied into the game folder, with their recorded SHA-256
        $missing = Read-InstallManifests $gm
        if ($missing.Count -gt 0) {
            Write-Finding "info" "[i] Notice: $($missing.Count) file(s) listed in an install manifest are missing (e.g. $($missing[0]))"
        }

        # A.4. Base Game Engine Integrity & Malware Audit (projectzomboid.jar)
        if ($doScanEngine) {
            $engineRes = Audit-PzEngine $gm $reportLines
            if ($engineRes) {
                $statsCritical += $engineRes.Critical
                $statsWarning += $engineRes.Warnings
            }
        }
    }

    # A.5. Java environment variables apply to every JVM the user starts, including the game's
    foreach ($var in "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS") {
        foreach ($level in "User", "Machine") {
            $val = [Environment]::GetEnvironmentVariable($var, $level)
            if ($val) {
                Write-Finding "info" "[i] Notice: $level environment variable $var is set: $val"
                Test-JvmOptions $val "$level environment variable $var"
            }
        }
    }
}

# 6. EXECUTION B: Audit Native Binaries in Workshop & User Mod Dirs
foreach ($n in $modNatives) { Test-NativeBinary $n (Get-WorkshopScope $n.FullName) "" }

function Write-ScanResult($name, $path, $res, $okLine, $expiredNotice = $null, $fileHash = "") {
    if ($expiredNotice) {
        Write-Host "  [!] Notice: $expiredNotice" -ForegroundColor Yellow
        $reportLines.Add("  [!] Notice: $expiredNotice")
    }
    if ($res.UserExceptions -and $res.UserExceptions.Count -gt 0) {
        $script:statsUserExceptions += $res.UserExceptions.Count
        foreach ($ue in $res.UserExceptions) {
            $h = $ue.Hit
            Write-Host "  [USER EXCEPTION] $name ($($h.Entry) -> $($h.Pattern) [SHA-256 verified])" -ForegroundColor DarkCyan
            $reportLines.Add("  [USER EXCEPTION] $path ($($h.Entry) -> $($h.Pattern) [SHA-256 verified])")
        }
    }
    if ($res.Critical.Count -gt 0) {
        $script:statsCritical++
        Write-Host "  [CRITICAL THREAT] $name" -ForegroundColor Red
        Write-Host "    Path: $path" -ForegroundColor DarkGray
        $reportLines.Add("[CRITICAL THREAT] $path")
        $res.Critical | ForEach-Object { $_.Text } | Select-Object -Unique | ForEach-Object {
            Write-Host "    [!] $_" -ForegroundColor Red
            $reportLines.Add("    - $_")
        }
        $res.Warning | ForEach-Object { $_.Text } | Select-Object -Unique | ForEach-Object {
            Write-Host "    [*] $_" -ForegroundColor Yellow
            $reportLines.Add("    - $_")
        }
    } elseif ($res.Warning.Count -gt 0) {
        $script:statsWarning++
        Write-Host "  [WARNING / SUSPICIOUS] $name" -ForegroundColor Yellow
        Write-Host "    Path: $path" -ForegroundColor DarkGray
        $reportLines.Add("[WARNING / SUSPICIOUS] $path")
        $res.Warning | ForEach-Object { $_.Text } | Select-Object -Unique | ForEach-Object {
            Write-Host "    [*] $_" -ForegroundColor Yellow
            $reportLines.Add("    - $_")
        }
        foreach ($w in $res.Warning) {
            $script:promptWarnings.Add([PSCustomObject]@{
                TargetName = $name
                TargetPath = $path
                FileHash = $fileHash
                Hit = $w
            })
        }
    } else {
        $suffix = if ($res.UserExceptions -and $res.UserExceptions.Count -gt 0) {
            " (with $($res.UserExceptions.Count) verified user exception$([string](if ($res.UserExceptions.Count -gt 1) { 's' } else { '' })))"
        } else { "" }
        Write-Host "  $okLine$suffix" -ForegroundColor $(if ($okLine.StartsWith("[KNOWN")) { "Cyan" } else { "Green" })
        $reportLines.Add("  $okLine$suffix")
    }
}

# 7. EXECUTION C: Scan JAR Packages
if ($allJars.Count -gt 0) {
    Write-Host "`nScanning $($allJars.Count) Mod JAR Packages..." -ForegroundColor DarkGray
    $jarIdx = 0

    foreach ($jar in $allJars) {
        $jarIdx++
        Show-ModProgressBar $jarIdx $allJars.Count $jar.Name

        $scope = Get-FileScope $jar.FullName
        $classHashes = $null
        if (-not $scope) { $classHashes = [System.Collections.Generic.List[string]]::new() }
        $hits = [System.Collections.Generic.List[object]]::new()
        try {
            Add-JarHits $hits $jar.FullName $classHashes
        } catch {
            Clear-ModProgressBar
            Write-Host "  [?] Notice: Could not read $($jar.Name) (file locked or in use)." -ForegroundColor Yellow
            continue
        }

        # A game-folder jar repackaging only manifest-verified classes (e.g. an AOT cache) inherits their scope
        $origin = ""
        if (-not $scope -and $classHashes.Count -gt 0) {
            $scopes = @($classHashes | ForEach-Object { $manifestHashes[$_] } | Select-Object -Unique)
            if ($scopes.Count -eq 1 -and $scopes[0]) { $scope = $scopes[0]; $origin = ", classes match install manifest" }
        } elseif ($scope -and -not (Get-WorkshopScope $jar.FullName)) {
            $origin = ", identical to Workshop copy"
        }

        Clear-ModProgressBar
        $jarHash = try { (Get-FileHash -LiteralPath $jar.FullName -Algorithm SHA256).Hash.ToLower() } catch { "" }
        $expNotice = Get-ExpiredExceptionNotice $jarHash "" $jar.Name ""
        $res = Select-UnlistedHits $hits $scope $jarHash $jar.Name
        $okLine = if (Test-InScope $scope $wsPZ3D) { "[KNOWN FRAMEWORK] $($jar.Name) (PZ3D Camera Engine - Verified 0 Malicious Payloads$origin)" }
            elseif (Test-InScope $scope $wsZombieBuddy) { "[KNOWN FRAMEWORK] $($jar.Name) (Mod Loader - Verified 0 Malicious Payloads$origin)" }
            elseif (Test-InScope $scope $wsRichPres) { "[OK] $($jar.Name) (Discord Rich Presence - Verified Clean$origin)" }
            else { "[OK] $($jar.Name) ($($jar.Directory.Name)$origin)" }
        Write-ScanResult $jar.Name $jar.FullName $res $okLine $expNotice $jarHash
    }
}

# 8. EXECUTION D: Scan Loose .class Files
# D.1. Game folder overrides: verified against install manifests, then scanned with the manifest owner's scope
if ($gameRootClasses.Count -gt 0) {
    Write-Host "`nScanning $($gameRootClasses.Count) Game Folder Code Overrides..." -ForegroundColor DarkGray
    $byScope = @{}
    $modified = [System.Collections.Generic.List[string]]::new()
    $unmanaged = [System.Collections.Generic.List[string]]::new()
    $cIdx = 0
    foreach ($cf in $gameRootClasses) {
        $cIdx++
        if ($cIdx % 50 -eq 0 -or $cIdx -eq $gameRootClasses.Count) {
            Show-ModProgressBar $cIdx $gameRootClasses.Count "Checking game folder classes"
        }
        try { $bytes = [System.IO.File]::ReadAllBytes($cf.FullName) } catch { continue }
        $gm = ($targets.GameRoot | Where-Object { $cf.FullName.StartsWith("$_\", [System.StringComparison]::OrdinalIgnoreCase) } | Select-Object -First 1)
        $rel = $cf.FullName.Substring($gm.Length + 1).Replace('\', '/')
        $scope = ""
        $m = $manifestFiles[$cf.FullName.ToLower()]
        if (-not $m) { $unmanaged.Add($cf.FullName) }
        elseif ($m[0] -ne [PzmgClassFile]::Sha256($bytes)) { $modified.Add($cf.FullName) }
        else { $scope = $m[1] }
        if (-not $byScope.ContainsKey($scope)) { $byScope[$scope] = [System.Collections.Generic.List[object]]::new() }
        Add-ClassHits $byScope[$scope] $bytes $rel
    }
    Clear-ModProgressBar

    foreach ($f in $modified) { Write-Finding "critical" "[CRITICAL] Game folder class changed since its mod installed it: $f" }
    if ($unmanaged.Count -gt 0) {
        Write-Finding "warning" "[WARNING / SUSPICIOUS] $($unmanaged.Count) game folder class override(s) not listed in any install manifest:"
        $unmanaged | Select-Object -First 10 | ForEach-Object { Write-Host "    [*] $_" -ForegroundColor Yellow; $reportLines.Add("    - $_") }
    }
    foreach ($scope in $byScope.Keys) {
        $label = if ($scope) { "Game folder overrides from $scope" } else { "Game folder overrides without a verified source" }
        Write-ScanResult $label $label (Select-UnlistedHits $byScope[$scope] $scope) "[OK] Game folder overrides$(if ($scope) { " from $scope" }) clean."
    }
}

# D.2. Loose classes in Workshop / user mod folders (Full Deep Scan)
if ($allLooseClasses.Count -gt 0) {
    Write-Host "`nScanning $($allLooseClasses.Count) Loose Class Overrides..." -ForegroundColor DarkGray
    $byScope = @{}
    $cIdx = 0
    foreach ($cf in $allLooseClasses) {
        $cIdx++
        if ($cIdx % 50 -eq 0 -or $cIdx -eq $allLooseClasses.Count) {
            Show-ModProgressBar $cIdx $allLooseClasses.Count "Checking loose classes ($cIdx/$($allLooseClasses.Count))"
        }
        try { $bytes = [System.IO.File]::ReadAllBytes($cf.FullName) } catch { continue }
        $scope = Get-WorkshopScope $cf.FullName
        if (-not $byScope.ContainsKey($scope)) { $byScope[$scope] = [System.Collections.Generic.List[object]]::new() }
        Add-ClassHits $byScope[$scope] $bytes "$($cf.Directory.Name)/$($cf.Name)"
    }
    Clear-ModProgressBar
    foreach ($scope in $byScope.Keys) {
        $label = if ($scope) { "Loose classes in Workshop item $scope" } else { "Loose classes outside the Workshop" }
        Write-ScanResult $label $label (Select-UnlistedHits $byScope[$scope] $scope) "[OK] $label clean."
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
if ($doScanGameRoot) {
    Write-Host "Game Folder Overrides: $($gameRootClasses.Count) Scanned"
}
if ($doScanLooseClasses) {
    Write-Host "Loose Class Overrides: $($allLooseClasses.Count) Scanned"
} else {
    Write-Host "Loose Class Overrides: Skipped (Included in Full Deep Scan)"
}

if ($knownFrameworksFound.Count -gt 0) {
    Write-Host "Known Native Frameworks: $($knownFrameworksFound.Count) Audited ($($knownFrameworksFound -join ', '))" -ForegroundColor Cyan
}
if ($statsUserExceptions -gt 0) {
    Write-Host "User Exceptions:       $statsUserExceptions Active (SHA-256 Verified)" -ForegroundColor DarkCyan
}

if ($statsCritical -eq 0 -and $statsWarning -eq 0) {
    if ($knownFrameworksFound.Count -gt 0) {
        Write-Host "`nRESULT: ALL TARGETS CLEAN. No malicious payloads or unauthorized threats detected." -ForegroundColor Green
        Write-Host "Notice: $($knownFrameworksFound.Count) known 3rd-party framework(s) detected with elevated system hooks ($($knownFrameworksFound -join ', ')). Verified clean." -ForegroundColor Cyan
    } else {
        Write-Host "`nRESULT: ALL TARGETS CLEAN. No threats or unauthorized modifications detected." -ForegroundColor Green
    }
    if ($statsUserExceptions -gt 0) {
        Write-Host "Notice: $statsUserExceptions user exception(s) active and verified by SHA-256." -ForegroundColor DarkCyan
    }
} elseif ($statsCritical -eq 0 -and $statsWarning -gt 0) {
    Write-Host "`nRESULT: CAUTION. $statsWarning item(s) have suspicious indicators requiring review." -ForegroundColor Yellow
} else {
    Write-Host "`nRESULT: DANGER! $statsCritical critical threat(s) detected! Do not launch game." -ForegroundColor Red
}

# Saved next to the script: under Steam --launch the working directory is the game folder
$reportPath = if ($selfPath) { Join-Path (Split-Path $selfPath) "pz_mod_scan_report.txt" } else { ".\pz_mod_scan_report.txt" }
try {
    $reportLines.Add("")
    $reportLines.Add("==========================================================================")
    $reportLines.Add("Notice: PZ-ModGuard is an independent open-source tool and is not affiliated")
    $reportLines.Add("with The Indie Stone or Valve Corporation. Scanned mods are run at your own risk.")
    [System.IO.File]::WriteAllLines($reportPath, $reportLines)
    Write-Host "`nDetailed report saved to: $reportPath" -ForegroundColor DarkGray
} catch {}

# Interactive Post-Scan Prompt for Warnings
if (-not $env:PZMG_PROFILE -and $promptWarnings.Count -gt 0) {
    Write-Host ""
    $saveEx = Read-Host "Would you like to save any detected warning(s) as a trusted SHA-256 exception? [Y/N]"
    if ($saveEx -match '^[Yy]') {
        Write-Host "`nDetected Suspicious Items:" -ForegroundColor Cyan
        $wIdx = 0
        foreach ($pw in $promptWarnings) {
            $wIdx++
            Write-Host "  [$wIdx] $($pw.TargetName)" -ForegroundColor Yellow
            Write-Host "      Entry:   $($pw.Hit.Entry)" -ForegroundColor DarkGray
            Write-Host "      Warning: $($pw.Hit.Pattern)" -ForegroundColor DarkGray
            $hashShow = if ($pw.FileHash) { $pw.FileHash } else { $pw.Hit.Hash }
            Write-Host "      SHA-256: $hashShow" -ForegroundColor DarkGray
        }
        $picks = Read-Host "`nEnter item number(s) to trust (e.g. '1' or '1,2'), or [C] to cancel"
        if ($picks -and $picks -notmatch '^[Cc]') {
            $indices = $picks -split '[, ]+' | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ }
            foreach ($idx in $indices) {
                if ($idx -ge 1 -and $idx -le $promptWarnings.Count) {
                    $item = $promptWarnings[$idx - 1]
                    $choiceType = Read-Host "Trust entire file '$($item.TargetName)' [F] or only this specific class [C]? [Default: F]"
                    $targetHash = if ($choiceType -match '^[Cc]' -and $item.Hit.Hash) { $item.Hit.Hash } else {
                        if ($item.FileHash) { $item.FileHash } else { $item.Hit.Hash }
                    }
                    $targetEntry = if ($choiceType -match '^[Cc]') { $item.Hit.Entry } else { "*" }
                    $targetPattern = if ($choiceType -match '^[Cc]') { $item.Hit.Pattern } else { "*" }
                    $comment = Read-Host "Enter optional note for this exception (e.g. '$($item.TargetName) LLM mod')"

                    $newEx = [PSCustomObject]@{
                        sha256 = $targetHash.ToLower()
                        target = $item.TargetName
                        entry = $targetEntry
                        pattern = $targetPattern
                        comment = $comment
                        date_added = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                    }
                    $script:userExceptions.Add($newEx)
                }
            }
            Save-UserExceptions
            Write-Host "`n[+] Exceptions saved to $(Get-ExceptionsFilePath)!" -ForegroundColor Green
            Write-Host "Future scans will verify this SHA-256 hash and suppress the warning as long as the file is unmodified." -ForegroundColor DarkCyan
            Start-Sleep -Seconds 2
        }
    }
}

# Exit code for the --launch gate in the batch header: 20 = critical, 10 = warnings only, 0 = clean.
# Anything else (e.g. 1 from a crash) means the scan did not finish and the gate asks before launching.
exit $(if ($statsCritical -gt 0) { 20 } elseif ($statsWarning -gt 0) { 10 } else { 0 })
