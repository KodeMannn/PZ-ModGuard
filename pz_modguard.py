#!/usr/bin/env python3
"""
Project Zomboid - Advanced Java & Binary Mod Guard
Cross-Platform Core Security Scanner (Linux, SteamOS / Steam Deck, Windows, macOS)
Version 2.6.0
Discord: https://discord.gg/5rmsnwMPez
Coded with the assistance of Google Gemini and Claude Code
Zero external dependencies - standard library only
"""

import fnmatch
import hashlib
import io
import os
import sys
import re
import json
import shutil
import subprocess
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

# Launcher scripts whose text is checked for JVM options (Windows .bat and Linux shell launchers)
LAUNCHER_SCRIPTS = [
    "ProjectZomboid64.bat", "ProjectZomboid32.bat", "ProjectZomboid64ShowConsole.bat",
    "ProjectZomboidOpenGLDebug64.bat", "ProjectZomboidServer.bat",
    "projectzomboid.sh", "ProjectZomboid64", "ProjectZomboid32", "start-server.sh"
]

WHITELISTED_AGENTS = {
    "-agentlib:zbNative", "-agentlib:pz3dLoader",
    "-agentlib:libzbNative", "-agentlib:libpz3dLoader"
}

STOCK_PZ_JARS = {"projectzomboid.jar"}

# This scanner's own files: skipped by full path, never by name
SELF_PATHS = {
    os.path.normcase(str((Path(__file__).resolve().parent / n).resolve()))
    for n in ("pz_modguard.py", "pz-modguard.sh", "PZ-ModGuard.bat")
}

# Trust is scoped to the Steam Workshop item a file comes from. Steam assigns these IDs, so a malicious mod
# cannot claim another mod's ID the way it can copy a folder name, file name or class name.
WS_ZOMBIEBUDDY = "ws:3619862853,ws:3807686870"
WS_PZ3D = "ws:3807334881"
WS_PZOPT = "ws:3805285544"
WS_VIEWPOINT = "ws:3809306528"
WS_RICHPRES = "ws:3785376350"
WS_CARPHYSICS = "ws:3796880595"

# Native binaries expected inside one Workshop item (or as a byte-identical copy of it in the game folder)
KNOWN_NATIVE_FRAMEWORKS = {
    "pz3dLoader.dll": (WS_PZ3D, "PZ3D 3D Camera Engine Hook (Native Windows C++ Binary)"),
    "libpz3dLoader.so": (WS_PZ3D, "PZ3D 3D Camera Engine Hook (Native Linux Binary)"),
    "zbNative.dll": (WS_ZOMBIEBUDDY, "ZombieBuddy Build 42 Native Hook Agent (Windows)"),
    "libzbNative.so": (WS_ZOMBIEBUDDY, "ZombieBuddy Build 42 Native Hook Agent (Linux)")
}

# Install manifests ("relative/path sha256" per line) that mods write into the game folder for their class overrides
INSTALL_MANIFESTS = {"pzopt-installed.txt": WS_PZOPT}

KNOWN_DEV_SCRIPTS = [
    f"{WS_CARPHYSICS}|build.ps1",
    f"{WS_CARPHYSICS}|test.ps1",
    f"{WS_CARPHYSICS}|build.sh",
    f"{WS_CARPHYSICS}|test.sh",
    f"{WS_PZOPT}|install.ps1",
    f"{WS_PZOPT}|install.sh"
]

# Tier 1: matched against string literals in the class
TIER_1_PATTERNS = [
    "discord.com/api/webhooks", "discordapp.com/api/webhooks",
    "api.telegram.org", "pastebin.com/raw", "iplogger", "grabify",
    "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe",
    "certutil", "bitsadmin", "curl.exe",
    "\\AppData\\Roaming\\discord", "\\AppData\\Local\\Google\\Chrome", "\\AppData\\Roaming\\Mozilla",
    "Start Menu\\Programs\\Startup",
    # Linux-specific persistence & reverse shell signatures
    "/bin/bash -i", "/bin/sh -i", "nc -e", "/dev/tcp/",
    ".config/discord", ".mozilla/firefox", ".config/google-chrome"
]
TIER_1_LOWER = [(p, p.lower()) for p in TIER_1_PATTERNS]

# Tier 2: exact field/method references ("owner.member") resolved from the constant pool...
TIER_2_REFS = [
    "java/net/URLClassLoader.<init>",
    "java/lang/ProcessBuilder.start", "java/lang/Runtime.exec",
    "javax/crypto/Cipher.init",
    "java/net/Socket.<init>", "java/net/ServerSocket.<init>",
    "java/net/URL.openConnection", "java/net/URL.openStream",
    "java/net/http/HttpClient.send", "java/net/http/HttpClient.sendAsync"
]
# ...plus whole constant-pool names, which also catch these being called through reflection
TIER_2_NAMES = ["defineClass", "defineHiddenClass", "java.lang.ProcessBuilder", "java.lang.Runtime"]

# "Scope|EntryPathPattern|PatternPattern" (fnmatch-style, case-insensitive). A rule whose last field is "*"
# never hides a Tier 1 hit.
SCOPED_WHITELIST = [
    # Base game: bundled Javacord library contains the Discord webhook API URL
    "engine|org/javacord/*|discord.com/api/webhooks",

    # ZombieBuddy: Java mod loader. Bundled ByteBuddy / ClassGraph / BouncyCastle library code
    f"{WS_ZOMBIEBUDDY}|net/bytebuddy/*|*",
    f"{WS_ZOMBIEBUDDY}|io/github/classgraph/*|*",
    f"{WS_ZOMBIEBUDDY}|nonapi/io/github/classgraph/*|*",
    f"{WS_ZOMBIEBUDDY}|zb/org/bouncycastle/*|*",
    f"{WS_ZOMBIEBUDDY}|win32-x86*/attach_hotspot_windows.dll|native",
    # ZombieBuddy itself: mod-approval window (subprocess), mod-author lookups (Steam API, GitHub)
    f"{WS_ZOMBIEBUDDY}|me/zed_0xff/zombie_buddy/frontend/SwingModApprovalFrontend.class|java/lang/ProcessBuilder.start",
    f"{WS_ZOMBIEBUDDY}|me/zed_0xff/zombie_buddy/*|java/net/http/HttpClient.send*",
    f"{WS_ZOMBIEBUDDY}|me/zed_0xff/zombie_buddy/PatchTransformer.class|defineClass",

    # Viewpoint: reads GPU utilization through Windows typeperf
    f"{WS_VIEWPOINT}|viewpoint/platform/GpuBusy.class|java/lang/ProcessBuilder.start",

    # Discord Rich Presence: local IPC socket to the Discord desktop app
    f"{WS_RICHPRES}|*LinuxIPC*|java/net/Socket.<init>",
    f"{WS_RICHPRES}|*IPCClient*|java/net/Socket.<init>",

    # PZ3D: compatibility check, self-updater, bundled ByteBuddy
    f"{WS_PZ3D}|*CompatibilityCheck*|java/net/URLClassLoader.<init>",
    f"{WS_PZ3D}|*SelfUpdater*|java/lang/ProcessBuilder.start",
    f"{WS_PZ3D}|*AgentBuilder*|java/net/URLClassLoader.<init>",
    f"{WS_PZ3D}|*ClassFileLocator*|java/net/URLClassLoader.<init>",
    f"{WS_PZ3D}|*net/bytebuddy/*|*",

    # PZ_Optimization: restart / uninstall helpers run hidden PowerShell (or /bin/sh), sound probe, updater (its
    # GitHub releases), override loader (reads its own jar resources), copies of stock classes that already exec
    f"{WS_PZOPT}|*pzopt/Restart.class|powershell.exe",
    f"{WS_PZOPT}|*pzopt/Uninstall.class|powershell.exe",
    f"{WS_PZOPT}|*pzopt/Restart.class|java/lang/ProcessBuilder.start",
    f"{WS_PZOPT}|*pzopt/Uninstall.class|java/lang/ProcessBuilder.start",
    f"{WS_PZOPT}|*pzopt/SoundProbe.class|java/lang/ProcessBuilder.start",
    f"{WS_PZOPT}|*zombie/GameWindow.class|java/lang/ProcessBuilder.start",
    f"{WS_PZOPT}|*pzopt/Updater.class|java/net/http/HttpClient.send*",
    f"{WS_PZOPT}|*pzopt/UpdateDelta*.class|java/net/http/HttpClient.send*",
    f"{WS_PZOPT}|*pzopt/Overrides.class|java/net/URL.openStream",
    f"{WS_PZOPT}|*gameStates/MainScreenState.class|java/lang/Runtime.exec"
]

STOCK_PZ_PACKAGES = {
    "astar", "com", "de", "fmod", "generation", "gnu", "imgui", "io",
    "jassimp", "javax", "kotlin", "meta-inf", "n3d", "okhttp3", "okio",
    "org", "oshi", "pl", "se", "windows", "macos", "linux", "zombie"
}

NATIVE_EXTS = {".exe", ".dll", ".so", ".vbs", ".bat", ".cmd", ".ps1", ".sh"}
SCAN_EXTS = {".jar", ".class"} | NATIVE_EXTS
ARCHIVE_RE = re.compile(r"\.(jar|zip)$", re.I)
EMBEDDED_NATIVE_RE = re.compile(r"\.(dll|exe|so|dylib|sys|bat|cmd|ps1|vbs|sh)$", re.I)
WORKSHOP_RE = re.compile(r"[\\/]workshop[\\/]content[\\/]108600[\\/](\d+)[\\/]")


def in_scope(scope: str, scope_list: str) -> bool:
    return bool(scope) and scope in scope_list.split(',')


def test_is_known_dev_script(scope: str, file_name: str) -> bool:
    for rule in KNOWN_DEV_SCRIPTS:
        scopes, name = rule.split('|')
        if in_scope(scope, scopes) and fnmatch.fnmatchcase(file_name.lower(), name.lower()):
            return True
    return False


def test_is_whitelisted(scope: str, entry_path: str, pattern: str, tier1: bool = False) -> bool:
    entry = entry_path.lower().replace('\\', '/')
    pat = pattern.lower()
    for rule in SCOPED_WHITELIST:
        scopes, entry_rule, pattern_rule = rule.split('|')
        if tier1 and pattern_rule == '*':
            continue
        if (in_scope(scope, scopes) and fnmatch.fnmatchcase(entry, entry_rule.lower())
                and fnmatch.fnmatchcase(pat, pattern_rule.lower())):
            return True
    return False


# --- JVM class file constant pool parser -------------------------------------------------------------------

def parse_class(b: bytes):
    """Returns None when the bytes are not a well-formed class file. Otherwise three newline-wrapped strings:
    every UTF-8 constant (names, descriptors, literals), string literals only, and every field/method
    reference resolved to "owner.member" (e.g. "java/lang/ProcessBuilder.start")."""
    if len(b) < 10 or b[:4] != b"\xca\xfe\xba\xbe":
        return None
    try:
        n = (b[8] << 8) | b[9]
        pos, size = 10, len(b)
        utf = [""] * n
        tag = bytearray(n)
        x = [0] * n
        y = [0] * n
        i = 1
        while i < n:
            t = b[pos]
            pos += 1
            tag[i] = t
            if t == 1:
                ln = (b[pos] << 8) | b[pos + 1]
                if pos + 2 + ln > size:
                    return None
                utf[i] = b[pos + 2:pos + 2 + ln].decode("utf-8", "replace")
                pos += 2 + ln
            elif t in (7, 8, 16, 19, 20):
                x[i] = (b[pos] << 8) | b[pos + 1]
                pos += 2
            elif t in (9, 10, 11, 12, 17, 18):
                x[i] = (b[pos] << 8) | b[pos + 1]
                y[i] = (b[pos + 2] << 8) | b[pos + 3]
                pos += 4
            elif t in (3, 4):
                pos += 4
            elif t in (5, 6):
                pos += 8
                i += 1
            elif t == 15:
                pos += 3
            else:
                return None
            i += 1
        if pos > size:
            return None
        literals, refs = [], []
        for i in range(1, n):
            t = tag[i]
            if t == 8:
                literals.append(utf[x[i]])
            elif t in (9, 10, 11):
                cls, nat = x[i], y[i]
                if tag[cls] != 7 or tag[nat] != 12:
                    return None
                refs.append(f"{utf[x[cls]]}.{utf[x[nat]]}")
        all_utf = [utf[i] for i in range(1, n) if tag[i] == 1]
        wrap = lambda items: "\n" + "\n".join(items) + "\n"
        return wrap(all_utf), wrap(literals), wrap(refs)
    except IndexError:
        return None


# --- Scanning: hits are (tier, entry, pattern, text); whitelisting is applied once the owner's scope is known ---

def scan_class(data: bytes, entry: str, hits: list):
    cp = parse_class(data)
    if cp is None:
        hits.append((2, entry, "invalid-class", f"{entry} -> not a valid class file (corrupt, encrypted or disguised)"))
        return
    all_utf, literals, refs = cp
    literals_lower = literals.lower()
    for p, p_lower in TIER_1_LOWER:
        if p_lower in literals_lower:
            hits.append((1, entry, p, f"{entry} -> contains '{p}'"))
    for p in TIER_2_REFS:
        if f"\n{p}\n" in refs:
            hits.append((2, entry, p, f"{entry} -> calls '{p}'"))
    for p in TIER_2_NAMES:
        if f"\n{p}\n" in all_utf:
            hits.append((2, entry, p, f"{entry} -> references '{p}'"))


def scan_archive(z: zipfile.ZipFile, prefix: str, hits: list, class_hashes=None):
    """Scans every entry of a zip/jar, recursing into nested archives and flagging embedded native binaries.
    class_hashes (optional) collects the SHA-256 of each top-level class entry."""
    for info in z.infolist():
        if info.is_dir():
            continue
        name = prefix + info.filename
        if info.filename.endswith(".class"):
            data = z.read(info)
            if class_hashes is not None:
                class_hashes.append(hashlib.sha256(data).hexdigest())
            scan_class(data, name, hits)
        elif ARCHIVE_RE.search(info.filename):
            try:
                with zipfile.ZipFile(io.BytesIO(z.read(info))) as inner:
                    scan_archive(inner, name + "!/", hits)
            except Exception:
                hits.append((2, name, "nested-archive", f"{name} -> nested archive could not be opened"))
        elif EMBEDDED_NATIVE_RE.search(info.filename):
            hits.append((2, name, "native", f"{name} -> embedded native binary / script"))


def select_unlisted_hits(hits: list, scope: str):
    critical, warning = [], []
    for h in hits:
        if test_is_whitelisted(scope, h[1], h[2], tier1=(h[0] == 1)):
            continue
        (critical if h[0] == 1 else warning).append(h)
    return critical, warning


# --- Scopes: "ws:<WorkshopID>" for files inside a Workshop item, "engine" for projectzomboid.jar, otherwise ---
# --- inherited from a byte-identical Workshop file or a verified install-manifest entry. Unscoped: no whitelist.

WORKSHOP_HASHES = {}    # sha256 -> scope of jars / native binaries inside Workshop items
MANIFEST_FILES = {}     # normalized full path -> (sha256, scope) from install manifests
MANIFEST_HASHES = {}    # sha256 -> scope, for recognizing manifest files repackaged into a jar


def norm(path) -> str:
    return os.path.normcase(os.path.abspath(str(path)))


def sha256_file(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def get_workshop_scope(path) -> str:
    m = WORKSHOP_RE.search(str(path))
    return f"ws:{m.group(1)}" if m else ""


def get_file_scope(path) -> str:
    s = get_workshop_scope(path)
    if s:
        return s
    try:
        return WORKSHOP_HASHES.get(sha256_file(path), "")
    except OSError:
        return ""


def read_install_manifests(gm: Path) -> list:
    """Loads install manifests from a game folder. Returns manifest entries that are missing on disk."""
    missing = []
    for name, scope in INSTALL_MANIFESTS.items():
        mf = gm / name
        if not mf.is_file():
            continue
        for line in mf.read_text(encoding="utf-8", errors="ignore").splitlines():
            if not line or line.startswith('#') or ' ' not in line:
                continue
            rel, sha = line.split(' ', 1)
            full = gm / rel
            if not full.exists():
                missing.append(str(full))
                continue
            MANIFEST_FILES[norm(full)] = (sha.strip().lower(), scope)
            MANIFEST_HASHES[sha.strip().lower()] = scope
    return missing


def find_files(root, exts: set) -> list:
    """One recursive walk collecting files with the given extensions (symlinked folders are not followed)."""
    found = []
    for d, _, files in os.walk(root, onerror=lambda e: None):
        for f in files:
            if os.path.splitext(f)[1].lower() in exts:
                found.append(Path(d) / f)
    return found


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


# --- Auto-Scan Setup: writes Project Zomboid's Steam Launch Options so every launch runs a Quick Scan first. ---
# Steam keeps them per account in userdata/<id>/config/localconfig.vdf (apps > 108600 > LaunchOptions) and
# rewrites that file when it exits, so Steam must be closed while it is edited.

OUR_LAUNCH_PREFIX_RE = re.compile(r'"[^"]*(PZ-ModGuard\.bat|pz-modguard\.sh)" --launch ', re.I)
VDF_TOKEN_RE = re.compile(r'"((?:[^"\\]|\\.)*)"|[{}]|//[^\n]*')
INSTALL_DIR = Path.home() / ".local" / "share" / "pz-modguard"


def new_launch_options(current: str, prefix) -> str:
    """Adds (or with prefix=None removes) "<script>" --launch in front of %command%, keeping the user's own options."""
    opts = OUR_LAUNCH_PREFIX_RE.sub("", current)
    if not prefix:
        return "" if opts.strip() == "%command%" else opts
    if "%command%" in opts:
        return opts.replace("%command%", f"{prefix} %command%", 1)
    return f"{prefix} %command% {opts}".rstrip()


def set_steam_launch_options(vdf_path: Path, prefix) -> str:
    with open(vdf_path, encoding="utf-8", newline="") as f:
        text = f.read()
    app_path = "userlocalconfigstore/software/valve/steam/apps/108600"
    stack, key, app_open, value = [], None, -1, None
    for m in VDF_TOKEN_RE.finditer(text):
        t = m.group(0)
        if t.startswith("//"):
            continue
        if t == "{":
            stack.append((key or "").lower())
            key = None
            if "/".join(stack) == app_path:
                app_open = m.end()
        elif t == "}":
            if stack:
                stack.pop()
        elif key is None:
            key = m.group(1)
        else:
            if "/".join(stack) == app_path and key.lower() == "launchoptions":
                value = m
            key = None
    if app_open < 0:
        return "skipped (Project Zomboid has not been played on this account)"
    current = re.sub(r"\\(.)", r"\1", value.group(1)) if value else ""
    new = new_launch_options(current, prefix)
    if new == current:
        return "already up to date"
    quoted = '"' + new.replace("\\", "\\\\").replace('"', '\\"') + '"'
    if value:
        text = text[:value.start()] + quoted + text[value.end():]
    else:
        text = text[:app_open] + f'\n\t\t\t\t\t\t"LaunchOptions"\t\t{quoted}' + text[app_open:]
    shutil.copy2(vdf_path, vdf_path.with_name(vdf_path.name + ".pzmg-backup"))
    with open(vdf_path, "w", encoding="utf-8", newline="") as f:
        f.write(text)
    return f"Launch Options set to: {new}" if new else "Launch Options cleared"


def steam_running() -> bool:
    for comm in Path("/proc").glob("[0-9]*/comm"):
        try:
            if comm.read_text().strip() == "steam":
                return True
        except OSError:
            pass
    return False


def install_auto_scan(remove: bool = False):
    if platform.system() == "Windows":
        print(f"\n{COLOR_YELLOW}[!] On Windows, use PZ-ModGuard.bat for Auto-Scan Setup.{COLOR_RESET}")
        return
    home = Path.home()
    roots = {Path(os.path.realpath(r)) for r in (
        home / ".local/share/Steam", home / ".steam/steam", home / ".steam/root",
        home / ".var/app/com.valvesoftware.Steam/.local/share/Steam") if (r / "userdata").is_dir()}
    vdfs = sorted(v for r in roots for v in (r / "userdata").glob("*/config/localconfig.vdf"))
    if not vdfs:
        print(f"\n{COLOR_RED}[!] Steam was not found, so the Launch Options cannot be set automatically.{COLOR_RESET}")
        return
    if steam_running():
        print(f"\n{COLOR_YELLOW}Steam is running. It overwrites its settings when it exits, so it has to be closed first.{COLOR_RESET}")
        if not input("Close Steam now? [Y/N]: ").strip().lower().startswith("y"):
            print("Cancelled. Nothing was changed.")
            return
        if shutil.which("steam"):
            subprocess.Popen(["steam", "-shutdown"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(60):
            if not steam_running():
                break
            time.sleep(1)
        if steam_running():
            print(f"{COLOR_RED}[!] Steam is still running. Close it, then choose this option again. Nothing was changed.{COLOR_RESET}")
            return
    prefix = None
    if not remove:
        # A fixed copy, so the Launch Options keep working after the download is moved or deleted
        src = Path(__file__).resolve().parent
        INSTALL_DIR.mkdir(parents=True, exist_ok=True)
        for name in ("pz_modguard.py", "pz-modguard.sh"):
            if (src / name).resolve() != (INSTALL_DIR / name).resolve():
                shutil.copy2(src / name, INSTALL_DIR / name)
            (INSTALL_DIR / name).chmod(0o755)
        prefix = f'"{INSTALL_DIR / "pz-modguard.sh"}" --launch'
        print(f"\n{COLOR_GREEN}Installed scanner: {INSTALL_DIR}{COLOR_RESET}")
    for vdf in vdfs:
        account = vdf.parent.parent.name
        try:
            print(f"  Steam account {account}: {set_steam_launch_options(vdf, prefix)}")
        except Exception as e:
            print(f"  {COLOR_RED}Steam account {account}: failed ({e}){COLOR_RESET}")
        if not remove and ".var/app/com.valvesoftware.Steam" in str(vdf):
            print(f"  {COLOR_YELLOW}Note: Flatpak Steam may not be able to run scripts in {INSTALL_DIR}.{COLOR_RESET}")
    if remove:
        print(f"\n{COLOR_GREEN}Auto-Scan removed. You can delete {INSTALL_DIR}.{COLOR_RESET}")
    else:
        print(f"\n{COLOR_GREEN}Done. Start Steam: every Project Zomboid launch now runs a Quick Scan first.{COLOR_RESET}")
        print(f"{COLOR_GRAY}A backup of each changed file was saved as localconfig.vdf.pzmg-backup.{COLOR_RESET}")


def game_dir_of(p: Path) -> Path:
    """Steam's Linux build keeps the jar and launcher one level down: ProjectZomboid/projectzomboid/."""
    if not (p / "projectzomboid.jar").exists() and (p / "projectzomboid" / "projectzomboid.jar").exists():
        return p / "projectzomboid"
    return p


def discover_targets() -> dict:
    targets = {
        "Workshop": [],
        "GameRoot": [],
        "UserMods": []
    }

    cwd = game_dir_of(Path.cwd())
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
            gm = game_dir_of(gm)
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

    pz_non_stock_packages = set()
    hits = []
    total_classes = 0

    try:
        with zipfile.ZipFile(jar_path, 'r') as z:
            for info in z.infolist():
                if info.filename.endswith(".class"):
                    total_classes += 1
                    parts = info.filename.split('/')
                    if parts[0].lower() not in STOCK_PZ_PACKAGES:
                        pz_non_stock_packages.add(f"{parts[0]}.{parts[1]}" if len(parts) > 2 else parts[0])
            scan_archive(z, "", hits)
    except Exception as e:
        print(f"  {COLOR_YELLOW}[?] Notice: Could not read projectzomboid.jar ({e}){COLOR_RESET}")
        return {"Critical": 0, "Warnings": 0, "NonStock": 0, "Classes": 0}

    critical, warning = select_unlisted_hits(hits, "engine")
    pz_critical = [f"{h[1]} -> contains '{h[2]}'" for h in critical]
    # Tier 2 only matters for classes injected by mods: stock engine code legitimately uses these APIs
    pz_injected_warnings = [f"{h[1]} -> {h[2]}" for h in warning if h[1].split('/')[0].lower() not in STOCK_PZ_PACKAGES]

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


class Scan:
    """Report state shared by the scan phases."""

    def __init__(self, report_lines: list):
        self.report_lines = report_lines
        self.critical = 0
        self.warning = 0
        self.known_frameworks_found = []

    def finding(self, severity: str, msg: str):
        color = {"critical": COLOR_RED, "warning": COLOR_YELLOW}.get(severity, COLOR_CYAN)
        if severity == "critical":
            self.critical += 1
        elif severity == "warning":
            self.warning += 1
        print(f"  {color}{msg}{COLOR_RESET}")
        self.report_lines.append(f"  {msg}")

    def jvm_options(self, text: str, source: str):
        """JVM options that load code before the game starts: agents run with full control over the JVM."""
        for m in re.finditer(r'-(agentlib|agentpath|javaagent):[^\s"\']+', text):
            if m.group(0) not in WHITELISTED_AGENTS:
                self.finding("critical", f"[CRITICAL] Unauthorized JVM Agent in {source}: {m.group(0)}")
        for m in re.finditer(r'-Xbootclasspath[^\s"\']*', text):
            self.finding("critical", f"[CRITICAL] Boot classpath override in {source}: {m.group(0)}")

    def native_binary(self, n: Path, scope: str, where: str):
        if n.name in KNOWN_NATIVE_FRAMEWORKS:
            expected, desc = KNOWN_NATIVE_FRAMEWORKS[n.name]
            if in_scope(scope, expected):
                if n.name not in self.known_frameworks_found:
                    self.known_frameworks_found.append(n.name)
                print(f"  {COLOR_CYAN}[KNOWN NATIVE FRAMEWORK] {n.name} ({desc}){COLOR_RESET}")
                self.report_lines.append(f"  [KNOWN NATIVE FRAMEWORK] {n} - {desc}")
            else:
                self.finding("critical", f"[CRITICAL] {n.name} is named like {desc} but does not match its Workshop copy: {n}")
        elif test_is_known_dev_script(scope, n.name):
            print(f"  {COLOR_GRAY}[i] Notice: Non-executing dev/install script: {n.name}{COLOR_RESET}")
            self.report_lines.append(f"  [i] Notice: Non-executing dev/install script: {n}")
        elif not test_is_whitelisted(scope, n.name, "native"):
            self.finding("critical", f"[CRITICAL] Unauthorized Native Binary{where}: {n}")

    def result(self, name: str, path: str, critical: list, warning: list, ok_line: str):
        if critical:
            self.critical += 1
            print(f"  {COLOR_RED}[CRITICAL THREAT] {name}{COLOR_RESET}")
            print(f"    {COLOR_GRAY}Path: {path}{COLOR_RESET}")
            self.report_lines.append(f"[CRITICAL THREAT] {path}")
            for text in dict.fromkeys(h[3] for h in critical):
                print(f"    {COLOR_RED}[!] {text}{COLOR_RESET}")
                self.report_lines.append(f"    - {text}")
            for text in dict.fromkeys(h[3] for h in warning):
                print(f"    {COLOR_YELLOW}[*] {text}{COLOR_RESET}")
                self.report_lines.append(f"    - {text}")
        elif warning:
            self.warning += 1
            print(f"  {COLOR_YELLOW}[WARNING / SUSPICIOUS] {name}{COLOR_RESET}")
            print(f"    {COLOR_GRAY}Path: {path}{COLOR_RESET}")
            self.report_lines.append(f"[WARNING / SUSPICIOUS] {path}")
            for text in dict.fromkeys(h[3] for h in warning):
                print(f"    {COLOR_YELLOW}[*] {text}{COLOR_RESET}")
                self.report_lines.append(f"    - {text}")
        else:
            color = COLOR_CYAN if ok_line.startswith("[KNOWN") else COLOR_GREEN
            print(f"  {color}{ok_line}{COLOR_RESET}")
            self.report_lines.append(f"  {ok_line}")


def main(profile=None):
    print(f"{COLOR_CYAN}================================================================={COLOR_RESET}")
    print(f"{COLOR_CYAN}       PROJECT ZOMBOID - ADVANCED JAVA & BINARY MOD GUARD        {COLOR_RESET}")
    print(f"{COLOR_DARK_CYAN}                        Version {VERSION}                            {COLOR_RESET}")
    print(f"{COLOR_GRAY}            Discord: https://discord.gg/5rmsnwMPez               {COLOR_RESET}")
    print(f"{COLOR_GRAY}   Coded with the assistance of Google Gemini and Claude Code    {COLOR_RESET}")
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
            p = game_dir_of(p)
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

    if profile:
        user_choice = profile
    else:
        print(f"\n{COLOR_CYAN}================================================================={COLOR_RESET}")
        print(f"{COLOR_CYAN}                      SELECT SCAN PROFILE                        {COLOR_RESET}")
        print(f"{COLOR_CYAN}================================================================={COLOR_RESET}")
        print(f"  {COLOR_WHITE}[1] Quick Scan      - Workshop & User Mods (Fastest, ~1.5s) [DEFAULT]{COLOR_RESET}")
        print(f"  {COLOR_WHITE}[2] Full Deep Scan  - Complete Audit (Base Engine + Workshop + Overrides){COLOR_RESET}")
        print(f"  {COLOR_WHITE}[3] Base Engine     - projectzomboid.jar Integrity & Security Audit{COLOR_RESET}")
        print(f"  {COLOR_WHITE}[4] Custom Target   - Scan a specific Mod Folder or .JAR file{COLOR_RESET}")
        print(f"  {COLOR_WHITE}[5] Custom Game Dir - Point to a GOG / Standalone / Custom PZ Folder{COLOR_RESET}")
        print(f"  {COLOR_WHITE}[6] Auto-Scan Setup - Scan automatically every time Project Zomboid starts (Steam){COLOR_RESET}")
        print(f"  {COLOR_WHITE}[7] Remove Auto-Scan{COLOR_RESET}")
        print(f"  {COLOR_GRAY}[Q] Quit / Cancel{COLOR_RESET}")
        print(f"{COLOR_CYAN}================================================================={COLOR_RESET}\n")

        # In non-interactive piped environments, default to "1"
        try:
            user_choice = input("Press [ENTER] for Quick Scan [1], or enter [1-7, Q]: ").strip()
        except EOFError:
            user_choice = "1"
    if user_choice in ("6", "7"):
        install_auto_scan(remove=(user_choice == "7"))
        return

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
        pz_dir = game_dir_of(pz_dir)
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

    do_scan_game_root = do_scan_launcher or do_scan_engine

    # Collect files: one walk per folder, sorted into jars, loose classes and native binaries / scripts
    all_jars = []
    all_loose_classes = []
    # Loose classes in a game folder sit on the classpath ahead of projectzomboid.jar ("." comes first), so they
    # replace engine code at launch. They are scanned in every profile that audits the game folder.
    game_root_classes = []
    mod_natives = []
    user_mod_dirs = [norm(um) + os.sep for um in targets["UserMods"]]

    def add_mod_files(root, jars: bool, classes: bool, natives: bool):
        for f in find_files(root, SCAN_EXTS):
            ext = f.suffix.lower()
            if ext == ".jar":
                if jars:
                    all_jars.append(f)
            elif ext == ".class":
                if classes:
                    all_loose_classes.append(f)
            elif natives and norm(f) not in SELF_PATHS:
                mod_natives.append(f)
            # Jars / native binaries inside Workshop items: byte-identical copies in a game folder inherit their scope
            if do_scan_game_root and ext in (".jar", ".dll", ".so") and get_workshop_scope(f):
                WORKSHOP_HASHES[sha256_file(f)] = get_workshop_scope(f)

    if custom_path:
        cp = Path(custom_path)
        if cp.is_file():
            if cp.suffix.lower() == ".jar":
                all_jars.append(cp)
            elif cp.suffix.lower() == ".class":
                all_loose_classes.append(cp)
        else:
            add_mod_files(cp, True, True, True)
    else:
        for ws in targets["Workshop"]:
            if do_scan_workshop or do_scan_game_root:
                add_mod_files(ws, do_scan_workshop, do_scan_workshop and do_scan_loose_classes, do_scan_workshop)
        if do_scan_user_mods:
            for um in targets["UserMods"]:
                add_mod_files(um, True, do_scan_loose_classes, True)
        if do_scan_game_root:
            for gm in targets["GameRoot"]:
                for f in find_files(gm, {".jar", ".class"}):
                    nf = norm(f)
                    if ("jre64" in f.parts or "jre" in f.parts or any(nf.startswith(u) for u in user_mod_dirs)
                            or (norm(f.parent) == norm(gm) and f.name in STOCK_PZ_JARS)):
                        continue
                    (all_jars if f.suffix.lower() == ".jar" else game_root_classes).append(f)

    print(f"\n{COLOR_GREEN}Profile Selected: {scan_profile_name}{COLOR_RESET}")
    print(f"{COLOR_WHITE}Items Queued for Inspection:{COLOR_RESET}")
    if do_scan_engine:
        print(f"  {COLOR_DARK_CYAN}- Base Game Engine Audit (projectzomboid.jar Deep Malware & Integrity Scan){COLOR_RESET}")
    if all_jars:
        print(f"  {COLOR_DARK_CYAN}- {len(all_jars)} Mod JAR Archives{COLOR_RESET}")
    if game_root_classes:
        print(f"  {COLOR_DARK_CYAN}- {len(game_root_classes)} Game Folder Code Overrides (loaded ahead of projectzomboid.jar){COLOR_RESET}")
    if all_loose_classes:
        print(f"  {COLOR_DARK_CYAN}- {len(all_loose_classes)} Loose Class Overrides{COLOR_RESET}")
    if do_scan_launcher:
        print(f"  {COLOR_DARK_CYAN}- Game Launcher Config (ProjectZomboid64.json, launcher scripts, Java environment variables){COLOR_RESET}")
    if custom_path:
        print(f"  {COLOR_DARK_CYAN}- Custom Target: {custom_path}{COLOR_RESET}")
    print(f"  {COLOR_DARK_CYAN}- All Locations for Rogue Native Binaries (.dll, .so, .exe, scripts){COLOR_RESET}")

    print(f"\n{COLOR_GREEN}Starting {scan_profile_name}...{COLOR_RESET}")

    report_lines = [
        f"Project Zomboid Mod Security Scan Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Scan Profile: {scan_profile_name}",
        "=========================================================================="
    ]
    scan = Scan(report_lines)

    # A. Audit Game Root Directories
    if do_scan_game_root:
        for gm in targets["GameRoot"]:
            p_gm = Path(gm)
            print(f"\n{COLOR_GRAY}Auditing Main Game Directory: {gm}{COLOR_RESET}")
            report_lines.append(f"Main Game Directory: {gm}")

            # A.1. Launcher Audit: JSON config, launcher scripts
            if do_scan_launcher:
                cfg_path = p_gm / "ProjectZomboid64.json"
                if cfg_path.exists():
                    try:
                        cfg = json.loads(cfg_path.read_text(encoding="utf-8", errors="ignore"))
                        scan.jvm_options(" ".join(cfg.get("vmArgs", [])), "ProjectZomboid64.json")
                        for cp in cfg.get("classpath", []):
                            if cp and cp != "." and cp not in STOCK_PZ_JARS:
                                scan.finding("info", f"[i] Notice: Launcher classpath includes '{cp}' (scanned below)")
                    except Exception:
                        pass
                for s in LAUNCHER_SCRIPTS:
                    sp = p_gm / s
                    if sp.is_file() and sp.stat().st_size < 1_000_000:
                        scan.jvm_options(sp.read_text(encoding="utf-8", errors="ignore"), s)

            # A.2. Audit Native Binaries in Game Root
            for n in p_gm.glob("*"):
                if n.is_file() and n.suffix.lower() in NATIVE_EXTS and norm(n) not in SELF_PATHS:
                    is_stock = (n.name in STOCK_DLLS or n.name in STOCK_SOS or n.name in STOCK_SCRIPTS
                                or n.name.startswith("ProjectZomboid"))
                    if not is_stock:
                        scan.native_binary(n, get_file_scope(n), " in Game Root")

            # A.3. Install manifests: class overrides a mod copied into the game folder, with their recorded SHA-256
            missing = read_install_manifests(p_gm)
            if missing:
                scan.finding("info", f"[i] Notice: {len(missing)} file(s) listed in an install manifest are missing (e.g. {missing[0]})")

            # A.4. Base Game Engine Integrity & Malware Audit (projectzomboid.jar)
            if do_scan_engine:
                engine_res = audit_pz_engine(gm, report_lines)
                scan.critical += engine_res["Critical"]
                scan.warning += engine_res["Warnings"]

        # A.5. Java environment variables apply to every JVM started from this environment, including the game's
        for var in ("JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS"):
            val = os.environ.get(var)
            if val:
                scan.finding("info", f"[i] Notice: environment variable {var} is set: {val}")
                scan.jvm_options(val, f"environment variable {var}")

    # B. Audit Native Binaries in Workshop & User Mod Dirs
    for n in mod_natives:
        scan.native_binary(n, get_workshop_scope(n), "")

    # C. Scan JAR Packages
    if all_jars:
        print(f"\n{COLOR_GRAY}Scanning {len(all_jars)} Mod JAR Packages...{COLOR_RESET}")
        for idx, jar_path in enumerate(all_jars, 1):
            show_progress_bar(idx, len(all_jars), jar_path.name)
            scope = get_file_scope(jar_path)
            class_hashes = None if scope else []
            hits = []
            try:
                with zipfile.ZipFile(jar_path, 'r') as z:
                    scan_archive(z, "", hits, class_hashes)
            except Exception as e:
                clear_progress_bar()
                print(f"  {COLOR_YELLOW}[?] Notice: Could not read {jar_path.name} ({e}){COLOR_RESET}")
                continue

            # A game-folder jar repackaging only manifest-verified classes (e.g. an AOT cache) inherits their scope
            origin = ""
            if not scope and class_hashes:
                scopes = {MANIFEST_HASHES.get(h, "") for h in class_hashes}
                if len(scopes) == 1 and "" not in scopes:
                    scope = scopes.pop()
                    origin = ", classes match install manifest"
            elif scope and not get_workshop_scope(jar_path):
                origin = ", identical to Workshop copy"

            clear_progress_bar()
            critical, warning = select_unlisted_hits(hits, scope)
            if in_scope(scope, WS_PZ3D):
                ok_line = f"[KNOWN FRAMEWORK] {jar_path.name} (PZ3D Camera Engine - Verified 0 Malicious Payloads{origin})"
            elif in_scope(scope, WS_ZOMBIEBUDDY):
                ok_line = f"[KNOWN FRAMEWORK] {jar_path.name} (Mod Loader - Verified 0 Malicious Payloads{origin})"
            elif in_scope(scope, WS_RICHPRES):
                ok_line = f"[OK] {jar_path.name} (Discord Rich Presence - Verified Clean{origin})"
            else:
                ok_line = f"[OK] {jar_path.name} ({jar_path.parent.name}{origin})"
            scan.result(jar_path.name, str(jar_path), critical, warning, ok_line)

    # D. Scan Loose .class Files
    # D.1. Game folder overrides: verified against install manifests, then scanned with the manifest owner's scope
    if game_root_classes:
        print(f"\n{COLOR_GRAY}Scanning {len(game_root_classes)} Game Folder Code Overrides...{COLOR_RESET}")
        by_scope = {}
        modified, unmanaged = [], []
        for idx, cf in enumerate(game_root_classes, 1):
            if idx % 50 == 0 or idx == len(game_root_classes):
                show_progress_bar(idx, len(game_root_classes), "Checking game folder classes")
            try:
                data = cf.read_bytes()
            except OSError:
                continue
            gm = next((g for g in targets["GameRoot"] if norm(cf).startswith(norm(g) + os.sep)), str(cf.parent))
            rel = os.path.relpath(cf, gm).replace(os.sep, '/')
            scope = ""
            m = MANIFEST_FILES.get(norm(cf))
            if not m:
                unmanaged.append(str(cf))
            elif m[0] != hashlib.sha256(data).hexdigest():
                modified.append(str(cf))
            else:
                scope = m[1]
            scan_class(data, rel, by_scope.setdefault(scope, []))
        clear_progress_bar()

        for f in modified:
            scan.finding("critical", f"[CRITICAL] Game folder class changed since its mod installed it: {f}")
        if unmanaged:
            scan.finding("warning", f"[WARNING / SUSPICIOUS] {len(unmanaged)} game folder class override(s) not listed in any install manifest:")
            for f in unmanaged[:10]:
                print(f"    {COLOR_YELLOW}[*] {f}{COLOR_RESET}")
                report_lines.append(f"    - {f}")
        for scope, hits in by_scope.items():
            label = f"Game folder overrides from {scope}" if scope else "Game folder overrides without a verified source"
            critical, warning = select_unlisted_hits(hits, scope)
            scan.result(label, label, critical, warning, f"[OK] {label} clean." if scope else "[OK] Game folder overrides clean.")

    # D.2. Loose classes in Workshop / user mod folders (Full Deep Scan)
    if all_loose_classes:
        print(f"\n{COLOR_GRAY}Scanning {len(all_loose_classes)} Loose Class Overrides...{COLOR_RESET}")
        by_scope = {}
        for idx, cf in enumerate(all_loose_classes, 1):
            if idx % 50 == 0 or idx == len(all_loose_classes):
                show_progress_bar(idx, len(all_loose_classes), f"Checking loose classes ({idx}/{len(all_loose_classes)})")
            try:
                data = cf.read_bytes()
            except OSError:
                continue
            scan_class(data, f"{cf.parent.name}/{cf.name}", by_scope.setdefault(get_workshop_scope(cf), []))
        clear_progress_bar()
        for scope, hits in by_scope.items():
            label = f"Loose classes in Workshop item {scope}" if scope else "Loose classes outside the Workshop"
            critical, warning = select_unlisted_hits(hits, scope)
            scan.result(label, label, critical, warning, f"[OK] {label} clean.")

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
    if do_scan_game_root:
        print(f"Game Folder Overrides: {len(game_root_classes)} Scanned")
    if do_scan_loose_classes:
        print(f"Loose Class Overrides: {len(all_loose_classes)} Scanned")
    else:
        print("Loose Class Overrides: Skipped (Included in Full Deep Scan)")

    known_frameworks_found = scan.known_frameworks_found
    stats_critical, stats_warning = scan.critical, scan.warning
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

    # Saved next to the script: under Steam --launch the working directory is the game folder
    report_path = Path(__file__).resolve().parent / "pz_mod_scan_report.txt"
    try:
        report_path.write_text("\n".join(report_lines), encoding="utf-8")
        print(f"\n{COLOR_GRAY}Detailed report saved to: {report_path}{COLOR_RESET}")
    except Exception:
        pass

    # Exit code for the --launch gate in pz-modguard.sh: 20 = critical, 10 = warnings only, 0 = clean.
    # Anything else (e.g. 1 from a crash) means the scan did not finish and the gate asks before launching.
    return 20 if stats_critical else 10 if stats_warning else 0


if __name__ == "__main__":
    # --profile N skips the menu (used by pz-modguard.sh --launch)
    args = sys.argv[1:]
    sys.exit(main(args[args.index("--profile") + 1] if "--profile" in args[:-1] else None))
