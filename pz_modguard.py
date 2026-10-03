#!/usr/bin/env python3
"""
Project Zomboid - Advanced Java & Binary Mod Guard
Cross-Platform Core Security Scanner (Linux, SteamOS / Steam Deck, Windows, macOS)
Version 2.6.0
Discord: https://discord.gg/5rmsnwMPez
Coded with the assistance of Google Gemini
Zero external dependencies - standard library only
"""

import os
import sys
import re
import json
import time
import zipfile
import platform
from pathlib import Path
from datetime import datetime

VERSION = "2.6.0"

# ANSI Colors
COLOR_RESET = "\033[0m"
COLOR_CYAN = "\033[96m"
COLOR_DARK_CYAN = "\033[36m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_RED = "\033[91m"
COLOR_WHITE = "\033[97m"
COLOR_GRAY = "\033[90m"

# Stock Engine Binaries
STOCK_DLLS = {
    "bink2w64.dll", "bink64.dll", "fmod.dll", "fmodintegration64.dll", "fmodintegration32.dll",
    "fmodstudio.dll", "fmod32.dll", "imgui-java64.dll", "jassimp64.dll", "jnidispatch.dll",
    "Lighting64.dll", "Lighting32.dll", "PZBullet64.dll", "PZBullet32.dll", "PZClipper64.dll",
    "PZClipper32.dll", "PZPathFind64.dll", "PZPathFind32.dll", "PZPopMan64.dll", "PZPopMan32.dll",
    "RakNet64.dll", "RakNet32.dll", "steam_api64.dll", "steam_api.dll", "ZNetJNI64.dll",
    "ZNetJNI32.dll", "ZNetNoSteam64.dll", "ZNetNoSteam32.dll"
}

STOCK_SOS = {
    "libbink2w64.so", "libbink64.so", "libfmod.so", "libfmodintegration64.so", "libfmodintegration32.so",
    "libfmodstudio.so", "libfmod32.so", "libimgui-java64.so", "libjassimp64.so", "libjnidispatch.so",
    "libLighting64.so", "libLighting32.so", "libPZBullet64.so", "libPZBullet32.so", "libPZClipper64.so",
    "libPZClipper32.so", "libPZPathFind64.so", "libPZPathFind32.so", "libPZPopMan64.so", "libPZPopMan32.so",
    "libRakNet64.so", "libRakNet32.so", "libsteam_api.so", "libsteam_api64.so", "libZNetJNI64.so",
    "libZNetJNI32.so", "libZNetNoSteam64.so", "libZNetNoSteam32.so"
}

STOCK_SCRIPTS = {
    "ProjectZomboid64.bat", "ProjectZomboid32.bat", "ProjectZomboid64ShowConsole.bat",
    "ProjectZomboidOpenGLDebug64.bat", "ProjectZomboidServer.bat",
    "projectzomboid.sh", "ProjectZomboid64", "ProjectZomboid32",
    "ProjectZomboid64.exe", "ProjectZomboid32.exe", "ProjectZomboid64ShowConsole.exe"
}

WHITELISTED_AGENTS = {
    "-agentlib:zbNative", "-agentlib:pz3dLoader",
    "-agentlib:libzbNative", "-agentlib:libpz3dLoader"
}

KNOWN_NATIVE_FRAMEWORKS = {
    "pz3dLoader.dll": "PZ3D 3D Camera Engine Hook (Native Windows C++ Binary)",
    "libpz3dLoader.so": "PZ3D 3D Camera Engine Hook (Native Linux Binary)",
    "zbNative.dll": "ZombieBuddy Build 42 Native Hook Agent (Windows)",
    "libzbNative.so": "ZombieBuddy Build 42 Native Hook Agent (Linux)"
}

KNOWN_DEV_SCRIPTS = [
    "CarPhysicsImproved|build.ps1",
    "CarPhysicsImproved|test.ps1",
    "CarPhysicsImproved|build.sh",
    "CarPhysicsImproved|test.sh",
    "PZ_Optimization|install.ps1",
    "PZ_Optimization|install.sh",
    "pzopt|install.ps1",
    "pzopt|install.sh"
]

TIER_1_PATTERNS = [
    b"discord.com/api/webhooks", b"discordapp.com/api/webhooks",
    b"api.telegram.org", b"pastebin.com/raw", b"iplogger", b"grabify",
    b"cmd.exe", b"powershell.exe", b"wscript.exe", b"cscript.exe",
    b"certutil", b"bitsadmin", b"curl.exe",
    b"\\AppData\\Roaming\\discord", b"\\AppData\\Local\\Google\\Chrome", b"\\AppData\\Roaming\\Mozilla",
    b"Start Menu\\Programs\\Startup",
    # Linux-specific persistence & reverse shell signatures
    b"/bin/bash -i", b"/bin/sh -i", b"nc -e", b"/dev/tcp/",
    b".config/discord", b".mozilla/firefox", b".config/google-chrome"
]

TIER_2_PATTERNS = [
    b"ClassLoader.defineClass", b"URLClassLoader",
    b"javax/crypto/Cipher", b"javax/crypto/spec/SecretKeySpec",
    b"java/net/Socket", b"java/net/ServerSocket",
    b"java/lang/ProcessBuilder", b"java/lang/Runtime.getRuntime"
]

SCOPED_WHITELIST = [
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
    "ZomboidRichPresence|LinuxIPC|Socket",
    "ZomboidRichPresence|IPCClient|Socket",
    "pz3dLoader|CompatibilityCheck|URLClassLoader",
    "pz3dLoader|SelfUpdater|ProcessBuilder",
    "pz3dLoader|AgentBuilder|URLClassLoader",
    "pz3dLoader|ClassFileLocator|URLClassLoader",
    "pz3dLoader|net/bytebuddy|URLClassLoader",
    "zbNative.dll",
    "libzbNative.so",
    "pz3dLoader.dll",
    "libpz3dLoader.so",
    "PZ_Optimization|Restart.class|powershell.exe",
    "PZ_Optimization|Uninstall.class|powershell.exe",
    "PZ_Optimization|Restart.class|java/lang/ProcessBuilder",
    "PZ_Optimization|Uninstall.class|java/lang/ProcessBuilder",
    "PZ_Optimization|SoundProbe.class|java/lang/ProcessBuilder",
    "PZ_Optimization|GameWindow.class|java/lang/ProcessBuilder",
    "pzopt|Restart.class|powershell.exe",
    "pzopt|Uninstall.class|powershell.exe",
    "pzopt|Restart.class|java/lang/ProcessBuilder",
    "pzopt|Uninstall.class|java/lang/ProcessBuilder",
    "pzopt|SoundProbe.class|java/lang/ProcessBuilder",
    "pzopt|GameWindow.class|java/lang/ProcessBuilder",
    "zombie|GameWindow.class|java/lang/ProcessBuilder",
    "PZ_Optimization|install.ps1",
    "pzopt|install.ps1",
    "ProjectZomboid64.json.pzopt-backup"
]

STOCK_PZ_PACKAGES = {
    "astar", "com", "de", "fmod", "generation", "gnu", "imgui", "io",
    "jassimp", "javax", "kotlin", "meta-inf", "n3d", "okhttp3", "okio",
    "org", "oshi", "pl", "se", "windows", "macos", "linux", "zombie"
}


def test_is_known_dev_script(file_path: str, file_name: str) -> bool:
    for rule in KNOWN_DEV_SCRIPTS:
        parts = rule.split('|')
        if len(parts) == 2:
            if parts[0].lower() in file_path.lower() and parts[1].lower() in file_name.lower():
                return True
        elif len(parts) == 1:
            if parts[0].lower() in file_path.lower() or parts[0].lower() in file_name.lower():
                return True
    return False


def test_is_whitelisted(parent_path: str, entry_path: str, pattern: str) -> bool:
    p_lower = parent_path.lower().replace('\\', '/')
    e_lower = entry_path.lower().replace('\\', '/')
    pat_lower = pattern.lower()

    for rule in SCOPED_WHITELIST:
        parts = rule.split('|')
        if len(parts) == 3:
            r0 = parts[0].lower().replace('\\', '/')
            r1 = parts[1].lower().replace('\\', '/')
            r2 = parts[2].lower()
            if r0 in p_lower and r1 in e_lower and r2 in pat_lower:
                return True
        elif len(parts) == 2:
            r0 = parts[0].lower().replace('\\', '/')
            r1 = parts[1].lower().replace('\\', '/')
            if r0 in p_lower and r1 in e_lower:
                return True
        elif len(parts) == 1:
            r0 = parts[0].lower().replace('\\', '/')
            if r0 in p_lower or r0 in e_lower:
                return True
    return False


def show_progress_bar(current: int, total: int, title: str):
    if total <= 0:
        return
    bar_len = 26
    pct = min(100, max(0, int(round((current / total) * 100))))
    filled = int(round((current / total) * bar_len))
    empty = bar_len - filled
    bar = "=" * filled + "-" * empty
    clean_title = (title[:29] + "...") if len(title) > 32 else title.ljust(32)
    sys.stdout.write(f"\r  [{bar}] {pct}% ({current}/{total}) {clean_title}")
    sys.stdout.flush()


def clear_progress_bar():
    sys.stdout.write("\r" + " " * 80 + "\r")
    sys.stdout.flush()


def parse_vdf_libraries(vdf_path: Path) -> list:
    roots = []
    try:
        content = vdf_path.read_text(encoding="utf-8", errors="ignore")
        for match in re.finditer(r'"path"\s+"([^"]+)"', content):
            raw = match.group(1).replace("\\\\", "/")
            p = Path(raw)
            if p.exists() and str(p) not in roots:
                roots.append(str(p))
    except Exception:
        pass
    return roots


def add_path_unique(target_list: list, p: Path):
    try:
        resolved = p.resolve()
        for existing in target_list:
            if Path(existing).resolve() == resolved:
                return
        target_list.append(str(resolved))
    except Exception:
        pass


def discover_targets() -> dict:
    targets = {
        "Workshop": [],
        "GameRoot": [],
        "UserMods": []
    }

    cwd = Path.cwd()
    # Portable check
    if ((cwd / "projectzomboid.jar").exists() or 
        (cwd / "ProjectZomboid64.exe").exists() or 
        (cwd / "ProjectZomboid64").exists() or 
        (cwd / "projectzomboid.sh").exists()):
        add_path_unique(targets["GameRoot"], cwd)
        if (cwd / "mods").exists():
            add_path_unique(targets["UserMods"], cwd / "mods")

    home = Path.home()
    is_windows = (platform.system() == "Windows")

    # Local user mods folder
    user_zomboid = home / "Zomboid" / "mods"
    if user_zomboid.exists():
        add_path_unique(targets["UserMods"], user_zomboid)

    library_roots = []

    if is_windows:
        # Check standard Windows paths
        win_candidates = [
            Path("C:/Program Files (x86)/Steam"),
            Path("C:/Steam"),
            Path("D:/SteamLibrary"),
            Path("E:/SteamLibrary"),
            Path("F:/SteamLibrary")
        ]
        # Query Windows Registry for SteamPath if winreg available
        try:
            import winreg
            for key_path, access in [
                (r"Software\Valve\Steam", winreg.HKEY_CURRENT_USER),
                (r"SOFTWARE\WOW6432Node\Valve\Steam", winreg.HKEY_LOCAL_MACHINE),
                (r"SOFTWARE\Valve\Steam", winreg.HKEY_LOCAL_MACHINE)
            ]:
                try:
                    with winreg.OpenKey(access, key_path) as k:
                        val, _ = winreg.QueryValueEx(k, "SteamPath")
                        if val:
                            p = Path(val.replace("/", "\\"))
                            if p.exists() and str(p) not in [str(x) for x in win_candidates]:
                                win_candidates.insert(0, p)
                            break
                except Exception:
                    pass
        except ImportError:
            pass

        for wc in win_candidates:
            if wc.exists():
                add_path_unique(library_roots, wc)
                vdf = wc / "steamapps" / "libraryfolders.vdf"
                if vdf.exists():
                    for lib in parse_vdf_libraries(vdf):
                        add_path_unique(library_roots, Path(lib))

        # GOG Galaxy & Standalone Windows registry / standard paths
        gog_paths = [
            Path("C:/GOG Games/Project Zomboid"),
            Path("D:/GOG Games/Project Zomboid"),
            Path("E:/GOG Games/Project Zomboid")
        ]
        for gp in gog_paths:
            if (gp / "projectzomboid.jar").exists():
                add_path_unique(targets["GameRoot"], gp)
                if (gp / "mods").exists():
                    add_path_unique(targets["UserMods"], gp / "mods")

    else:
        # Linux / SteamOS / Steam Deck / macOS
        linux_candidates = [
            home / ".local/share/Steam",
            home / ".steam/steam",
            home / ".steam/root",
            home / ".var/app/com.valvesoftware.Steam/.local/share/Steam",  # Flatpak
            home / "snap/steam/common/.local/share/Steam"                  # Snap
        ]
        for lc in linux_candidates:
            if lc.exists():
                add_path_unique(library_roots, lc)
                vdf = lc / "steamapps" / "libraryfolders.vdf"
                if vdf.exists():
                    for lib in parse_vdf_libraries(vdf):
                        add_path_unique(library_roots, Path(lib))

        # MicroSD mounts on Steam Deck (/run/media/mmcblk0p1 or /run/media/deck/*)
        run_media = Path("/run/media")
        if run_media.exists():
            try:
                for entry in run_media.rglob("steamapps/libraryfolders.vdf"):
                    lib_base = entry.parent.parent
                    add_path_unique(library_roots, lib_base)
                    for lib in parse_vdf_libraries(entry):
                        add_path_unique(library_roots, Path(lib))
            except Exception:
                pass

        # Linux GOG / Heroic / Lutris
        heroic_lutris = [
            home / "Games/Heroic/Project Zomboid",
            home / ".var/app/com.heroicgameslauncher.hgl/Games/Heroic/Project Zomboid",
            home / "Games/project-zomboid",
            home / "GOG Games/Project Zomboid"
        ]
        for hp in heroic_lutris:
            if (hp / "projectzomboid.jar").exists():
                add_path_unique(targets["GameRoot"], hp)
                if (hp / "mods").exists():
                    add_path_unique(targets["UserMods"], hp / "mods")

    # Resolve Workshop and GameRoot from discovered libraries
    for lib in library_roots:
        lp = Path(lib)
        ws = lp / "steamapps" / "workshop" / "content" / "108600"
        if ws.exists():
            add_path_unique(targets["Workshop"], ws)

        gm = lp / "steamapps" / "common" / "ProjectZomboid"
        if gm.exists():
            add_path_unique(targets["GameRoot"], gm)
            if (gm / "mods").exists():
                add_path_unique(targets["UserMods"], gm / "mods")

    return targets


def audit_pz_engine(gm_path: str, report_lines: list) -> dict:
    jar_path = Path(gm_path) / "projectzomboid.jar"
    if not jar_path.exists():
        return {"Critical": 0, "Warnings": 0, "NonStock": 0, "Classes": 0}

    print(f"\n{COLOR_CYAN}Auditing Base Game Engine (projectzomboid.jar)...{COLOR_RESET}")
    report_lines.append(f"Base Game Engine: {jar_path}")

    pz_critical = []
    pz_injected_warnings = []
    pz_non_stock_packages = set()
    total_classes = 0

    try:
        with zipfile.ZipFile(jar_path, 'r') as z:
            class_entries = [info for info in z.infolist() if info.filename.endswith(".class")]
            total = len(class_entries)
            total_classes = total

            for idx, info in enumerate(class_entries, 1):
                if idx % 1000 == 0 or idx == total:
                    show_progress_bar(idx, total, "Auditing projectzomboid.jar")

                entry_name = info.filename
                first_pkg = entry_name.split('/')[0].lower()
                if first_pkg not in STOCK_PZ_PACKAGES:
                    pz_non_stock_packages.add(first_pkg)

                data = z.read(info)

                # Tier 1 Pattern Scan
                for p in TIER_1_PATTERNS:
                    if p in data:
                        p_str = p.decode('ascii', errors='ignore')
                        if not test_is_whitelisted(str(jar_path), entry_name, p_str):
                            pz_critical.append(f"{entry_name} -> contains '{p_str}'")

                # Tier 2 Pattern Scan exclusively for 3rd-party injected classes
                if first_pkg not in STOCK_PZ_PACKAGES:
                    for p in TIER_2_PATTERNS:
                        if p in data:
                            p_str = p.decode('ascii', errors='ignore')
                            if not test_is_whitelisted(str(jar_path), entry_name, p_str):
                                pz_injected_warnings.append(f"{entry_name} -> calls '{p_str}'")

        clear_progress_bar()
    except Exception as e:
        clear_progress_bar()
        print(f"  {COLOR_YELLOW}[?] Notice: Could not read projectzomboid.jar ({e}){COLOR_RESET}")
        return {"Critical": 0, "Warnings": 0, "NonStock": 0, "Classes": 0}

    if pz_critical:
        print(f"  {COLOR_RED}[CRITICAL THREAT] Base Game Engine Compromised: {jar_path}{COLOR_RESET}")
        report_lines.append(f"  [CRITICAL THREAT] Base Game Engine Compromised: {jar_path}")
        for item in sorted(set(pz_critical)):
            print(f"    {COLOR_RED}[!] {item}{COLOR_RESET}")
            report_lines.append(f"    - {item}")
        print(f"    {COLOR_YELLOW}[!] ACTION REQUIRED: Run Steam 'Verify integrity of game files' immediately.{COLOR_RESET}")
        report_lines.append("    - ACTION REQUIRED: Verify integrity of game files via Steam.")
    elif pz_non_stock_packages:
        pkgs_str = ", ".join(sorted(pz_non_stock_packages))
        print(f"  {COLOR_CYAN}[i] Notice: projectzomboid.jar contains 3rd-party mod patches ({pkgs_str}){COLOR_RESET}")
        report_lines.append(f"  [i] Notice: projectzomboid.jar contains 3rd-party mod patches ({pkgs_str})")
        if pz_injected_warnings:
            print(f"  {COLOR_YELLOW}[WARNING / SUSPICIOUS] Injected mod classes contain elevated capabilities:{COLOR_RESET}")
            report_lines.append("  [WARNING / SUSPICIOUS] Injected mod classes contain elevated capabilities:")
            for item in sorted(set(pz_injected_warnings)):
                print(f"    {COLOR_YELLOW}[*] {item}{COLOR_RESET}")
                report_lines.append(f"    - {item}")
        else:
            print(f"  {COLOR_GREEN}[OK] Injected mod patches verified clean (0 malicious payloads).{COLOR_RESET}")
            report_lines.append("  [OK] Injected mod patches verified clean (0 malicious payloads).")
    else:
        print(f"  {COLOR_GREEN}[OK] Base Engine Verified Clean: projectzomboid.jar ({total_classes} classes verified, 0 threats){COLOR_RESET}")
        report_lines.append(f"  [OK] Base Engine Verified Clean: projectzomboid.jar ({total_classes} classes verified, 0 threats)")

    return {
        "Critical": len(pz_critical),
        "Warnings": len(pz_injected_warnings),
        "NonStock": len(pz_non_stock_packages),
        "Classes": total_classes
    }


def main():
    print(f"{COLOR_CYAN}================================================================={COLOR_RESET}")
    print(f"{COLOR_CYAN}       PROJECT ZOMBOID - ADVANCED JAVA & BINARY MOD GUARD        {COLOR_RESET}")
    print(f"{COLOR_DARK_CYAN}                        Version {VERSION}                            {COLOR_RESET}")
    print(f"{COLOR_GRAY}            Discord: https://discord.gg/5rmsnwMPez               {COLOR_RESET}")
    print(f"{COLOR_GRAY}          Coded with the assistance of Google Gemini             {COLOR_RESET}")
    print(f"{COLOR_CYAN}================================================================={COLOR_RESET}")

    targets = discover_targets()

    # Fallback if no game paths discovered
    if not targets["Workshop"] and not targets["GameRoot"]:
        print(f"\n{COLOR_YELLOW}[!] Could not automatically locate Project Zomboid installation.{COLOR_RESET}")
        custom_input = input("Enter path to Project Zomboid directory (or drag folder here, [Q] to quit): ").strip().strip('"').strip("'")
        if not custom_input or custom_input.lower().startswith("q"):
            print("Scan cancelled.")
            return
        p = Path(custom_input)
        if p.exists():
            targets["GameRoot"].append(str(p))
            if (p / "mods").exists():
                targets["UserMods"].append(str(p / "mods"))
            print(f"  {COLOR_GREEN}[+] Added Custom Game Directory: {p}{COLOR_RESET}")
        else:
            print(f"{COLOR_RED}[!] Directory not found: {custom_input}{COLOR_RESET}")
            return

    print(f"\n{COLOR_WHITE}Scanning Targets Discovered:{COLOR_RESET}")
    if targets["Workshop"]:
        print(f"  {COLOR_CYAN}[Steam Workshop Mods]{COLOR_RESET} ({len(targets['Workshop'])} Location):")
        for ws in targets["Workshop"]:
            print(f"    {COLOR_GRAY}-> {ws}{COLOR_RESET}")
    if targets["GameRoot"]:
        print(f"  {COLOR_CYAN}[Main Game Directory]{COLOR_RESET} ({len(targets['GameRoot'])} Location):")
        for gm in targets["GameRoot"]:
            print(f"    {COLOR_GRAY}-> {gm}{COLOR_RESET}")
    if targets["UserMods"]:
        print(f"  {COLOR_CYAN}[Local User Mods]{COLOR_RESET} ({len(targets['UserMods'])} Location):")
        for um in targets["UserMods"]:
            print(f"    {COLOR_GRAY}-> {um}{COLOR_RESET}")

    print(f"\n{COLOR_CYAN}================================================================={COLOR_RESET}")
    print(f"{COLOR_CYAN}                      SELECT SCAN PROFILE                        {COLOR_RESET}")
    print(f"{COLOR_CYAN}================================================================={COLOR_RESET}")
    print(f"  {COLOR_WHITE}[1] Quick Scan      - Workshop & User Mods (Fastest, ~1.5s) [DEFAULT]{COLOR_RESET}")
    print(f"  {COLOR_WHITE}[2] Full Deep Scan  - Complete Audit (Base Engine + Workshop + Overrides){COLOR_RESET}")
    print(f"  {COLOR_WHITE}[3] Base Engine     - projectzomboid.jar Integrity & Security Audit{COLOR_RESET}")
    print(f"  {COLOR_WHITE}[4] Custom Target   - Scan a specific Mod Folder or .JAR file{COLOR_RESET}")
    print(f"  {COLOR_WHITE}[5] Custom Game Dir - Point to a GOG / Standalone / Custom PZ Folder{COLOR_RESET}")
    print(f"  {COLOR_GRAY}[Q] Quit / Cancel{COLOR_RESET}")
    print(f"{COLOR_CYAN}================================================================={COLOR_RESET}\n")

    # In non-interactive piped environments, default to "1"
    try:
        user_choice = input("Press [ENTER] for Quick Scan [1], or enter [1-5, Q]: ").strip()
    except EOFError:
        user_choice = "1"

    if user_choice.lower().startswith("q"):
        print("\nScan cancelled by user.")
        return

    choice = user_choice if user_choice else "1"

    scan_profile_name = "Quick Scan"
    do_scan_workshop = False
    do_scan_user_mods = False
    do_scan_launcher = False
    do_scan_loose_classes = False
    do_scan_engine = False
    custom_path = None

    if choice == "1":
        scan_profile_name = "Quick Scan"
        do_scan_workshop = True
        do_scan_user_mods = True
        do_scan_launcher = True
    elif choice == "2":
        scan_profile_name = "Full Deep Scan"
        do_scan_workshop = True
        do_scan_user_mods = True
        do_scan_launcher = True
        do_scan_loose_classes = True
        do_scan_engine = True
    elif choice == "3":
        scan_profile_name = "Base Game Engine Audit"
        do_scan_engine = True
        do_scan_launcher = True
    elif choice == "4":
        scan_profile_name = "Custom Target Scan"
        raw_target = input("Enter or drag-and-drop the path to the Mod folder or .JAR file: ").strip().strip('"').strip("'")
        target_path = Path(raw_target)
        if not target_path.exists():
            print(f"{COLOR_RED}[!] Path not found: {raw_target}{COLOR_RESET}")
            return
        custom_path = str(target_path)
    elif choice == "5":
        scan_profile_name = "Custom Game Directory Audit"
        raw_pz = input("Enter path to Project Zomboid directory (or drag folder here): ").strip().strip('"').strip("'")
        pz_dir = Path(raw_pz)
        if not pz_dir.exists():
            print(f"{COLOR_RED}[!] Directory not found: {raw_pz}{COLOR_RESET}")
            return
        targets["GameRoot"] = [str(pz_dir)]
        if (pz_dir / "mods").exists():
            targets["UserMods"] = [str(pz_dir / "mods")]
        do_scan_engine = True
        do_scan_user_mods = True
        do_scan_launcher = True
        do_scan_loose_classes = True
    else:
        print(f"\n{COLOR_YELLOW}Unrecognized option '{choice}'. Defaulting to [1] Quick Scan.{COLOR_RESET}")
        scan_profile_name = "Quick Scan"
        do_scan_workshop = True
        do_scan_user_mods = True
        do_scan_launcher = True

    # Collect JARs and loose classes
    all_jars = []
    all_loose_classes = []

    if custom_path:
        cp = Path(custom_path)
        if cp.is_file():
            if cp.suffix.lower() == ".jar":
                all_jars.append(cp)
            elif cp.suffix.lower() == ".class":
                all_loose_classes.append(cp)
        else:
            all_jars.extend(list(cp.rglob("*.jar")))
            all_loose_classes.extend(list(cp.rglob("*.class")))
    else:
        if do_scan_workshop:
            for ws in targets["Workshop"]:
                all_jars.extend(list(Path(ws).rglob("*.jar")))
                if do_scan_loose_classes:
                    all_loose_classes.extend(list(Path(ws).rglob("*.class")))
        if do_scan_user_mods:
            for um in targets["UserMods"]:
                all_jars.extend(list(Path(um).rglob("*.jar")))
                if do_scan_loose_classes:
                    all_loose_classes.extend(list(Path(um).rglob("*.class")))
        if do_scan_engine:
            for gm in targets["GameRoot"]:
                p_gm = Path(gm)
                for j in p_gm.glob("*.jar"):
                    if j.name.lower() != "projectzomboid.jar":
                        all_jars.append(j)
                if do_scan_loose_classes:
                    for cf in p_gm.rglob("*.class"):
                        if "jre64" not in cf.parts:
                            all_loose_classes.append(cf)

    print(f"\n{COLOR_GREEN}Profile Selected: {scan_profile_name}{COLOR_RESET}")
    print(f"{COLOR_WHITE}Items Queued for Inspection:{COLOR_RESET}")
    if do_scan_engine:
        print(f"  {COLOR_DARK_CYAN}- Base Game Engine Audit (projectzomboid.jar Deep Malware & Integrity Scan){COLOR_RESET}")
    if all_jars:
        print(f"  {COLOR_DARK_CYAN}- {len(all_jars)} Mod JAR Archives{COLOR_RESET}")
    if all_loose_classes:
        print(f"  {COLOR_DARK_CYAN}- {len(all_loose_classes)} Loose Class Overrides{COLOR_RESET}")
    if do_scan_launcher:
        print(f"  {COLOR_DARK_CYAN}- Main Game Launcher Config (ProjectZomboid64.json){COLOR_RESET}")
    if custom_path:
        print(f"  {COLOR_DARK_CYAN}- Custom Target: {custom_path}{COLOR_RESET}")
    print(f"  {COLOR_DARK_CYAN}- All Locations for Rogue Native Binaries (.dll, .so, .exe, scripts){COLOR_RESET}")

    print(f"\n{COLOR_GREEN}Starting {scan_profile_name}...{COLOR_RESET}")

    report_lines = [
        f"Project Zomboid Mod Security Scan Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Scan Profile: {scan_profile_name}",
        "=========================================================================="
    ]

    stats_critical = 0
    stats_warning = 0
    known_frameworks_found = []

    # A. Audit Game Root Directories
    if do_scan_launcher or do_scan_engine:
        for gm in targets["GameRoot"]:
            p_gm = Path(gm)
            print(f"\n{COLOR_GRAY}Auditing Main Game Directory: {gm}{COLOR_RESET}")
            report_lines.append(f"Main Game Directory: {gm}")

            # Launcher config agent check
            if do_scan_launcher:
                cfg_path = p_gm / "ProjectZomboid64.json"
                if cfg_path.exists():
                    try:
                        with open(cfg_path, 'r', encoding='utf-8', errors='ignore') as f:
                            cfg = json.load(f)
                        vm_args = cfg.get("vmArgs", [])
                        for arg in vm_args:
                            if re.match(r"^-(agentlib|agentpath|javaagent):(.*)$", arg):
                                if arg not in WHITELISTED_AGENTS:
                                    stats_critical += 1
                                    msg = f"[CRITICAL] Unauthorized JVM Agent Injected into ProjectZomboid64.json: {arg}"
                                    print(f"  {COLOR_RED}{msg}{COLOR_RESET}")
                                    report_lines.append(f"  {msg}")
                    except Exception:
                        pass

            # Native binaries in Game Root
            for n in p_gm.glob("*"):
                if n.is_file() and n.suffix.lower() in [".dll", ".so", ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".sh"]:
                    if n.name in ["PZ-ModGuard.bat", "Scan-PZMods.bat", "pz-modguard.sh", "pz_modguard.py"]:
                        continue
                    is_stock = (
                        n.name in STOCK_DLLS or 
                        n.name in STOCK_SOS or 
                        n.name in STOCK_SCRIPTS or 
                        n.name.startswith("ProjectZomboid")
                    )
                    if not is_stock:
                        if n.name in KNOWN_NATIVE_FRAMEWORKS:
                            desc = KNOWN_NATIVE_FRAMEWORKS[n.name]
                            if n.name not in known_frameworks_found:
                                known_frameworks_found.append(n.name)
                            print(f"  {COLOR_CYAN}[KNOWN NATIVE FRAMEWORK] {n.name} ({desc}){COLOR_RESET}")
                            report_lines.append(f"  [KNOWN NATIVE FRAMEWORK] {n.resolve()} - {desc}")
                        elif test_is_known_dev_script(str(n.resolve()), n.name):
                            print(f"  {COLOR_GRAY}[i] Notice: Non-executing dev/install script: {n.name}{COLOR_RESET}")
                            report_lines.append(f"  [i] Notice: Non-executing dev/install script: {n.resolve()}")
                        elif test_is_whitelisted(str(n.resolve()), n.name, "native"):
                            pass
                        else:
                            stats_critical += 1
                            msg = f"[CRITICAL] Unauthorized Native Binary in Game Root: {n.resolve()}"
                            print(f"  {COLOR_RED}{msg}{COLOR_RESET}")
                            report_lines.append(f"  {msg}")

            # Base game engine audit
            if do_scan_engine:
                engine_res = audit_pz_engine(gm, report_lines)
                stats_critical += engine_res["Critical"]
                stats_warning += engine_res["Warnings"]

    # B. Audit Native Binaries in Workshop & User Mod Dirs
    non_root_dirs = []
    if do_scan_workshop:
        non_root_dirs.extend(targets["Workshop"])
    if do_scan_user_mods:
        non_root_dirs.extend(targets["UserMods"])
    if custom_path and Path(custom_path).is_dir():
        non_root_dirs.append(custom_path)

    for d in non_root_dirs:
        p_d = Path(d)
        for n in p_d.rglob("*"):
            if n.is_file() and n.suffix.lower() in [".exe", ".dll", ".so", ".vbs", ".bat", ".cmd", ".ps1", ".sh"]:
                if n.name in ["PZ-ModGuard.bat", "Scan-PZMods.bat", "pz-modguard.sh", "pz_modguard.py"]:
                    continue
                if n.name in KNOWN_NATIVE_FRAMEWORKS:
                    desc = KNOWN_NATIVE_FRAMEWORKS[n.name]
                    if n.name not in known_frameworks_found:
                        known_frameworks_found.append(n.name)
                    print(f"  {COLOR_CYAN}[KNOWN NATIVE FRAMEWORK] {n.name} ({desc}){COLOR_RESET}")
                    report_lines.append(f"  [KNOWN NATIVE FRAMEWORK] {n.resolve()} - {desc}")
                elif test_is_known_dev_script(str(n.resolve()), n.name):
                    print(f"  {COLOR_GRAY}[i] Notice: Non-executing dev/install script in mod folder: {n.name}{COLOR_RESET}")
                    report_lines.append(f"  [i] Notice: Non-executing dev/install script: {n.resolve()}")
                elif test_is_whitelisted(str(n.resolve()), n.name, "native"):
                    pass
                else:
                    stats_critical += 1
                    msg = f"[CRITICAL] Unauthorized Native Binary Detected: {n.resolve()}"
                    print(f"  {COLOR_RED}{msg}{COLOR_RESET}")
                    report_lines.append(f"  {msg}")

    # C. Scan JAR Packages
    if all_jars:
        print(f"\n{COLOR_GRAY}Scanning {len(all_jars)} Mod JAR Packages...{COLOR_RESET}")
        for idx, jar_path in enumerate(all_jars, 1):
            show_progress_bar(idx, len(all_jars), jar_path.name)
            jar_critical = []
            jar_warning = []

            try:
                with zipfile.ZipFile(jar_path, 'r') as z:
                    for info in z.infolist():
                        if info.filename.endswith(".class"):
                            data = z.read(info)
                            for p in TIER_1_PATTERNS:
                                if p in data:
                                    p_str = p.decode('ascii', errors='ignore')
                                    if not test_is_whitelisted(str(jar_path), info.filename, p_str):
                                        jar_critical.append(f"{info.filename.split('/')[-1]} -> contains '{p_str}'")
                            for p in TIER_2_PATTERNS:
                                if p in data:
                                    p_str = p.decode('ascii', errors='ignore')
                                    if not test_is_whitelisted(str(jar_path), info.filename, p_str):
                                        jar_warning.append(f"{info.filename.split('/')[-1]} -> calls '{p_str}'")
            except Exception as e:
                clear_progress_bar()
                print(f"  {COLOR_YELLOW}[?] Notice: Could not read {jar_path.name} ({e}){COLOR_RESET}")
                continue

            clear_progress_bar()
            if jar_critical:
                stats_critical += 1
                print(f"  {COLOR_RED}[CRITICAL THREAT] {jar_path.name}{COLOR_RESET}")
                print(f"    {COLOR_GRAY}Path: {jar_path.resolve()}{COLOR_RESET}")
                report_lines.append(f"[CRITICAL THREAT] {jar_path.resolve()}")
                for item in sorted(set(jar_critical)):
                    print(f"    {COLOR_RED}[!] {item}{COLOR_RESET}")
                    report_lines.append(f"    - {item}")
            elif jar_warning:
                stats_warning += 1
                print(f"  {COLOR_YELLOW}[WARNING / SUSPICIOUS] {jar_path.name}{COLOR_RESET}")
                print(f"    {COLOR_GRAY}Path: {jar_path.resolve()}{COLOR_RESET}")
                report_lines.append(f"[WARNING / SUSPICIOUS] {jar_path.resolve()}")
                for item in sorted(set(jar_warning)):
                    print(f"    {COLOR_YELLOW}[*] {item}{COLOR_RESET}")
                    report_lines.append(f"    - {item}")
            else:
                j_name = jar_path.name.lower()
                if "pz3dloader" in j_name:
                    print(f"  {COLOR_CYAN}[KNOWN FRAMEWORK] {jar_path.name} (PZ3D Camera Engine - Verified 0 Malicious Payloads){COLOR_RESET}")
                    report_lines.append(f"  [KNOWN FRAMEWORK] {jar_path.resolve()} (PZ3D - Verified Clean)")
                elif "zombiebuddy" in j_name:
                    print(f"  {COLOR_CYAN}[KNOWN FRAMEWORK] {jar_path.name} (Mod Loader - Verified 0 Malicious Payloads){COLOR_RESET}")
                    report_lines.append(f"  [KNOWN FRAMEWORK] {jar_path.resolve()} (ZombieBuddy - Verified Clean)")
                elif "richpresence" in j_name:
                    print(f"  {COLOR_GREEN}[OK] {jar_path.name} (Discord Rich Presence - Verified Clean){COLOR_RESET}")
                    report_lines.append(f"  [OK] {jar_path.resolve()} (Discord Rich Presence - Verified Clean)")
                else:
                    parent_dir_name = jar_path.parent.name
                    print(f"  {COLOR_GREEN}[OK] {jar_path.name} ({parent_dir_name}){COLOR_RESET}")
                    report_lines.append(f"  [OK] {jar_path.resolve()}")

    # D. Scan Loose .class Files
    if all_loose_classes:
        print(f"\n{COLOR_GRAY}Scanning {len(all_loose_classes)} Loose Class Overrides...{COLOR_RESET}")
        loose_critical = []
        loose_warning = []

        for idx, cf in enumerate(all_loose_classes, 1):
            if idx % 50 == 0 or idx == len(all_loose_classes):
                show_progress_bar(idx, len(all_loose_classes), f"Checking loose classes ({idx}/{len(all_loose_classes)})")
            try:
                data = cf.read_bytes()
                for p in TIER_1_PATTERNS:
                    if p in data:
                        p_str = p.decode('ascii', errors='ignore')
                        if not test_is_whitelisted(str(cf.resolve()), cf.name, p_str):
                            loose_critical.append(f"{cf.parent.name}/{cf.name} -> {p_str}")
                for p in TIER_2_PATTERNS:
                    if p in data:
                        p_str = p.decode('ascii', errors='ignore')
                        if not test_is_whitelisted(str(cf.resolve()), cf.name, p_str):
                            loose_warning.append(f"{cf.parent.name}/{cf.name} -> {p_str}")
            except Exception:
                pass

        clear_progress_bar()
        if loose_critical:
            stats_critical += 1
            print(f"  {COLOR_RED}[CRITICAL THREAT] Loose .class files flagged:{COLOR_RESET}")
            for item in sorted(set(loose_critical)):
                print(f"    {COLOR_RED}[!] {item}{COLOR_RESET}")
                report_lines.append(f"  [!] Loose Class: {item}")
        elif loose_warning:
            stats_warning += 1
            print(f"  {COLOR_YELLOW}[WARNING / SUSPICIOUS] Loose .class files flagged:{COLOR_RESET}")
            for item in sorted(set(loose_warning)):
                print(f"    {COLOR_YELLOW}[*] {item}{COLOR_RESET}")
                report_lines.append(f"  [*] Loose Class: {item}")
        else:
            print(f"  {COLOR_GREEN}[OK] All {len(all_loose_classes)} loose .class files clean.{COLOR_RESET}")
            report_lines.append(f"  [OK] All {len(all_loose_classes)} loose .class files clean.")

    # 9. Final Audit Summary
    print(f"\n{COLOR_CYAN}================================================================={COLOR_RESET}")
    print(f"{COLOR_CYAN}                        AUDIT SUMMARY                            {COLOR_RESET}")
    print(f"{COLOR_CYAN}================================================================={COLOR_RESET}")
    print(f"Profile Executed:      {scan_profile_name}")
    print(f"Workshop Locations:    {len(targets['Workshop'])}")
    print(f"Game Root Locations:   {len(targets['GameRoot'])}")
    print(f"User Mod Locations:    {len(targets['UserMods'])}")
    if do_scan_engine:
        print(f"Base Game Engines:     {len(targets['GameRoot'])} Audited")
    else:
        print("Base Game Engines:     Skipped (Included in Full Deep Scan)")
    print(f"Total Mod JARs:        {len(all_jars)} Scanned")
    if do_scan_loose_classes:
        print(f"Loose Class Overrides: {len(all_loose_classes)} Scanned")
    else:
        print("Loose Class Overrides: Skipped (Included in Full Deep Scan)")

    if known_frameworks_found:
        frameworks_str = ", ".join(known_frameworks_found)
        print(f"{COLOR_CYAN}Known Native Frameworks: {len(known_frameworks_found)} Audited ({frameworks_str}){COLOR_RESET}")

    if stats_critical == 0 and stats_warning == 0:
        if known_frameworks_found:
            frameworks_str = ", ".join(known_frameworks_found)
            print(f"\n{COLOR_GREEN}RESULT: ALL TARGETS CLEAN. No malicious payloads or unauthorized threats detected.{COLOR_RESET}")
            print(f"{COLOR_CYAN}Notice: {len(known_frameworks_found)} known 3rd-party framework(s) detected with elevated system hooks ({frameworks_str}). Verified clean.{COLOR_RESET}")
        else:
            print(f"\n{COLOR_GREEN}RESULT: ALL TARGETS CLEAN. No threats or unauthorized modifications detected.{COLOR_RESET}")
    elif stats_critical == 0 and stats_warning > 0:
        print(f"\n{COLOR_YELLOW}RESULT: CAUTION. {stats_warning} item(s) have suspicious indicators requiring review.{COLOR_RESET}")
    else:
        print(f"\n{COLOR_RED}RESULT: DANGER! {stats_critical} critical threat(s) detected! Do not launch game.{COLOR_RESET}")

    report_path = Path("pz_mod_scan_report.txt")
    try:
        report_path.write_text("\n".join(report_lines), encoding="utf-8")
        print(f"\n{COLOR_GRAY}Detailed report saved to: {report_path.resolve()}{COLOR_RESET}")
    except Exception:
        pass


if __name__ == "__main__":
    main()
