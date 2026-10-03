# PZ-ModGuard 🛡️
**Advanced Java & Binary Mod Security Guard for Project Zomboid (Build 42)**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Discord](https://img.shields.io/badge/Discord-Join%20Community-5865F2?logo=discord&logoColor=white)](https://discord.gg/5rmsnwMPez)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20SteamOS-blue.svg)]()
[![Game](https://img.shields.io/badge/Project%20Zomboid-Build%2042-darkgreen.svg)](https://projectzomboid.com/)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero-brightgreen.svg)]()
[![AI Assisted](https://img.shields.io/badge/Coded%20with-Google%20Gemini-8E75C2?logo=google&logoColor=white)]()
[![AI Assisted](https://img.shields.io/badge/Coded%20with-Claude%20Code-D97757?logo=claude&logoColor=white)]()

**PZ-ModGuard** is a fast, standalone, pre-launch security scanner engineered to protect Project Zomboid players from malicious Java mods, trojan droppers, and credential stealers. 

Starting in Build 42, Project Zomboid mods can execute compiled Java bytecode (`.jar` / `.class`) and native agents. Because traditional antivirus programs (like Windows Defender) scan Windows `.exe`/`.dll` binaries and are mostly blind to Java bytecode constant pools, **PZ-ModGuard** fills the gap with an in-memory JVM Constant Pool parser and heuristic threat detection engine.

> ℹ️ **Disclaimer:** This project was developed and coded with the assistance of Google Gemini and Claude Code.

---

## ⚡ Quick Start

### 🪟 Windows
1. **Download**: Grab [`PZ-ModGuard.bat`](https://github.com/KodeMannn/PZ-ModGuard/releases/latest) (single-file, zero dependencies).
2. **Run**: Double-click `PZ-ModGuard.bat` anywhere on your computer (desktop, workshop folder, or downloads).
3. **Choose Profile**: Press **[ENTER]** for the default **Quick Scan** (~1.5s), or select **[2] Full Deep Scan** to include the core game engine.
4. **Play Safe**: Review the color-coded report before launching Project Zomboid.
5. **Optional, recommended**: Run it again and choose **[6] Auto-Scan Setup** to scan automatically every time you start Project Zomboid from Steam ([details](#-scan-automatically-before-every-launch-steam)).

### 🐧 Linux & SteamOS (Steam Deck)
1. **Download**: Grab [`pz-modguard.sh`](https://github.com/KodeMannn/PZ-ModGuard/releases/latest) and [`pz_modguard.py`](https://github.com/KodeMannn/PZ-ModGuard/releases/latest), or download the `.tar.gz` bundle from releases.
2. **Run**: Open a terminal in the folder and run:
   ```bash
   chmod +x pz-modguard.sh pz_modguard.py
   ./pz-modguard.sh
   ```
   *(Or double-click `pz-modguard.sh` in your desktop file manager / Steam Deck Desktop Mode).*
3. **Choose Profile**: Press **[ENTER]** for **Quick Scan** or select **[2] Full Deep Scan**.
4. **Optional, recommended**: Run it again and choose **[6] Auto-Scan Setup** to scan automatically every time you start Project Zomboid from Steam ([details](#-scan-automatically-before-every-launch-steam)).

> **Zero Dependencies:** Requires no `pip`, no Node.js, and no external packages. Runs out-of-the-box on Windows 10 & 11 via native PowerShell-Batch polyglot, and on Linux/SteamOS via Python 3's built-in standard library (pre-installed on SteamOS and all standard Linux distros).

---

### 🔁 Scan Automatically Before Every Launch (Steam)
Run PZ-ModGuard and choose **[6] Auto-Scan Setup**. It:
1. Copies the scanner to a fixed folder (`%LOCALAPPDATA%\PZ-ModGuard` on Windows, `~/.local/share/pz-modguard` on Linux), so you can delete the download afterwards.
2. Offers to close Steam (Steam overwrites its settings when it exits).
3. Adds the scan to Project Zomboid's **Launch Options** in every Steam account on the PC that has played the game, keeping any options you already had (such as ZombieBuddy's `-agentlib:zbNative --`). A backup of each changed file is saved as `localconfig.vdf.pzmg-backup`.

**[7] Remove Auto-Scan** takes it out again. To set it up by hand instead, put this in front of your Launch Options (**Properties → General → Launch Options**):

| Platform | Launch Options |
| :--- | :--- |
| Windows | `"C:\path\to\PZ-ModGuard.bat" --launch %command%` |
| Linux / Steam Deck | `/path/to/pz-modguard.sh --launch %command%` |

Each launch runs a Quick Scan first. Only a clean result starts the game directly. If anything is found (warnings or critical threats), or the scan could not finish, the game does **not** start until you confirm. Anything other than Yes cancels the launch. On Linux that question is a `zenity` dialog. Without `zenity` the launch is blocked and the reason is written to Steam's log. The report is saved next to the script.

---

## 🚀 Scan Profiles & Automation

PZ-ModGuard features 5 selectable scan profiles and 2 Steam automation tools:

| Profile / Option | Target Coverage | Typical Duration | Best For |
| :--- | :--- | :--- | :--- |
| **`[1] Quick Scan`** *(Default)* | Steam Workshop mods, Local user mods, Launcher config | **~1.5 seconds** | Daily check after subscribing to new mods |
| **`[2] Full Deep Scan`** | Base engine (`projectzomboid.jar`), Workshop, Loose overrides, Game root | **~6 seconds** | Initial setup or after installing engine-level mods |
| **`[3] Base Engine Only`** | Dedicated `projectzomboid.jar` integrity audit & Game Root | **~4.5 seconds** | Verifying game engine integrity without scanning mods |
| **`[4] Custom Target`** | Any specific mod folder or `.jar` file (supports drag-and-drop) | **< 1 second** | Testing an individual mod from NexusMods/Discord |
| **`[5] Custom Game Dir`** | Point directly to any GOG, standalone, server, or custom folder | **~5 seconds** | GOG Galaxy, DRM-free copies, or dedicated servers |
| **`[6] Auto-Scan Setup`** | Configures Steam Launch Options for all local Steam accounts | **Instant** | Scanning mods automatically before every game launch |
| **`[7] Remove Auto-Scan`** | Removes PZ-ModGuard from Steam Launch Options | **Instant** | Reverting Steam launch options back to original state |
| **`[8] User Exceptions`** | Manage trusted SHA-256 exceptions (view, add, remove) | **Instant** | Suppressing known benign warnings (e.g. LLM mods) |

---

## 🔍 Key Features

* **⚡ Ultra-Fast In-Memory Engine:** Windows polyglot compiles an in-memory C# parser (`Add-Type`) and Linux executes native Python 3, scanning thousands of compiled classes per second and completing full audits in ~3 to 8 seconds with zero external dependencies.
* **🎮 Deep Base Engine Audit (`projectzomboid.jar`):** Audits all 23,800+ core game engine classes for trojans and backdoors without triggering false alarms on official engine code, while identifying 3rd-party injected mod packages (such as ZombieBuddy).
* **🌐 Universal Platform & GOG Support:** Full compatibility with:
  * **Steam Workshop** (`steamapps/workshop/content/108600`) across all drives (`C:`, `D:`, `E:`, external NVMe SSDs).
  * **GOG Galaxy & Standalone Installers** (`C:\GOG Games\Project Zomboid`, GOG registry keys, and custom drives).
  * **Portable Drop-in Execution:** Running `PZ-ModGuard.bat` directly from inside any game folder instantly recognizes it as the game root.
  * **Interactive Fallback:** Never crashes or aborts if installed in an unusual path—prompts for folder drag-and-drop.
  * **Local User Mods** (`%USERPROFILE%/Zomboid/mods` and `<GameRoot>/mods`).
* **⚙️ Launcher Integrity & Environment Check:** Inspects `ProjectZomboid64.json`, launcher scripts (`.bat`/`.sh`), and global Java environment variables (`JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`, `JDK_JAVA_OPTIONS`). Verifies that JVM agent arguments (`-agentlib:`, `-agentpath:`, `-javaagent:`) only reference trusted agents (like `zbNative`), and flags any `-Xbootclasspath` overrides.
* **🔬 High-Precision JVM Bytecode Parser:** Parses each class file's constant pool (`0xCAFEBABE`) and resolves every method / field reference to `owner.member` (e.g. `java/lang/ProcessBuilder.start`). Tier 1 checks string literals; Tier 2 checks exact references, plus names used through reflection (`defineClass`). Malformed, corrupted, or encrypted class files are flagged.
* **🎯 3-Tier Threat Engine:**
  * **Tier 1 (CRITICAL - Red):** Active malicious payloads (Discord webhooks, Telegram bots, token grabbers, shell invocation like `cmd.exe`/`powershell.exe`, Linux reverse shells, droppers like `curl`/`certutil`, and rogue `.exe`/`.dll`/`.vbs`/`.sh` files).
  * **Tier 2 (WARNING - Yellow):** Evasion and dropper patterns (in-memory classloaders like `ClassLoader.defineClass` used by modular trojans such as Fractureiser, string encryption ciphers like `javax.crypto.Cipher`, and raw TCP sockets).
  * **Tier 3 (CLEAN - Green):** Audited game reflection, rendering hooks, and math libraries.
* **🛡️ Workshop-Scoped Whitelisting:** Whitelist rules are `(Workshop ID | ClassPath | Pattern)`. Trust comes from the Steam Workshop item a file lives in, which a mod cannot fake, not from folder, file or class names. Copies in the game folder are trusted only when byte-identical to the Workshop file, or (for class overrides) when they match the SHA-256 in the installing mod's manifest. Tier 1 hits are never blanket-whitelisted.
* **📦 Full Surface Coverage:** Inspects `.jar` packages (including nested jars and embedded native binaries), loose `.class` files in the game folder (they load ahead of `projectzomboid.jar`, checked against install manifests such as *PZ_Optimization*'s `pzopt-installed.txt`), and native binaries / scripts.
* **🔁 Automatic Pre-Launch Steam Scanning:** Launches game through `--launch %command%`. Automatically audits mods prior to launch; clean launches proceed instantly, while threats or unmanaged overrides halt launch until reviewed.
* **📊 Visual UX & Progress Bar:** Profile selector menu, live ASCII percentage progress bar, Windows notification bar integration, and persistent terminal output.
* **📝 Automated Audit Logs:** Automatically saves a timestamped scan report to `pz_mod_scan_report.txt` for easy review or sharing.

---

## 🛡️ Threat Detection Matrix

| Threat Category | Example Signatures Detected | Severity |
| :--- | :--- | :--- |
| **Discord Webhooks / Exfiltration** | `discord.com/api/webhooks`, `discordapp.com/api/webhooks`, `api.telegram.org`, `pastebin.com/raw`, `iplogger`, `grabify` | **CRITICAL** |
| **Command Execution & Shells** | `cmd.exe`, `powershell.exe`, `wscript.exe`, `cscript.exe`, `/bin/bash -i`, `/bin/sh -i`, `nc -e`, `/dev/tcp/` | **CRITICAL** |
| **Payload Droppers & Downloaders** | `certutil`, `bitsadmin`, `curl.exe` | **CRITICAL** |
| **Info & Token Stealers** | Windows `\AppData\Roaming\discord`, Chrome User Data, Firefox profiles; Linux `.config/discord`, `.mozilla/firefox`, `.config/google-chrome` | **CRITICAL** |
| **Persistence Mechanisms** | Windows `\Microsoft\Windows\Start Menu\Programs\Startup` | **CRITICAL** |
| **Unauthorized Native Binaries** | Unwhitelisted `.exe`, `.dll`, `.so`, `.vbs`, `.bat`, `.cmd`, `.ps1`, `.sh` in mod folders or game root | **CRITICAL** |
| **Unauthorized JVM Agents & Overrides** | Unapproved `-agentlib:`, `-agentpath:`, `-javaagent:`, or `-Xbootclasspath` in launcher JSON, `.bat`/`.sh` scripts, or environment variables (`JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`, `JDK_JAVA_OPTIONS`) | **CRITICAL** |
| **Tampered Game Folder Overrides** | Loose `.class` files in game directory with SHA-256 hash mismatches against mod install manifests (`pzopt-installed.txt`) | **CRITICAL** |
| **Corrupt / Disguised Bytecode** | Malformed constant pools, truncated `.class` files, or non-class payloads claiming `0xCAFEBABE` | **WARNING** |
| **Bytecode Process Spawning** | Resolved constant pool method calls to `java/lang/ProcessBuilder.start`, `java/lang/Runtime.exec` | **WARNING** |
| **Network Exfiltration APIs** | Resolved constant pool method calls to `java/net/http/HttpClient.send`, `sendAsync`, `java/net/URL.openConnection`, `openStream` | **WARNING** |
| **In-Memory Droppers (Fractureiser)** | `java/net/URLClassLoader.<init>`, constant pool references to `defineClass`, `defineHiddenClass` | **WARNING** |
| **Obfuscated Ciphers / Encryption** | `javax/crypto/Cipher.init`, `SecretKeySpec` | **WARNING** |
| **Raw Network Sockets** | `java/net/Socket.<init>`, `java/net/ServerSocket.<init>` | **WARNING** |

---

## ℹ️ Pre-Audited Frameworks & Benign Mods

The following mods have been inspected and classified for specific, legitimate framework operations:
* **PZ3D** (`3807334881`): Uses a native C++ loader (`pz3dLoader.dll`), dynamic bytecode injection (`ByteBuddy`), and `SelfUpdater.class` (`ProcessBuilder`). Classified as a **Known Native Framework**; deeply audited for 0 hostile malware/stealers.
* **ZombieBuddy** (`3619862853` & `3807686870`): Uses ByteBuddy agent attachment (`ProcessBuilder`), native hook agent (`zbNative.dll`), and bundled cryptography libraries (`org.bouncycastle.*`).
* **Discord Rich Presence** (`3785376350` / `ZomboidRichPresence`): Connects to the local Discord desktop application via local IPC sockets (`LinuxIPC.class -> Socket`) to display game status on Discord.
* **Viewpoint** (`3809306528`): Uses `ProcessBuilder` in `GpuBusy.class` solely to query Windows native `typeperf.exe` for GPU utilization statistics.
* **PZ_Optimization** (`3805285544`): In-game settings menu buttons use helper calls to `powershell.exe` for game restart and backup restoration.
* **CarPhysicsImproved** (`3796880595`): Non-executing internal developer build scripts (`build.ps1`/`test.ps1`) left in `media\src\` are classified as harmless dev artifacts.

> **Continuous Security Guarantee:** Pre-audited frameworks are **never** given a blind bypass. Every single `.class` file inside them is continuously scanned for Tier 1 hostile malware signatures (webhooks, stealers, droppers). If a known framework is ever tampered with or compromised, ModGuard will immediately raise a critical threat alarm.

---

## 🔐 User-Defined SHA-256 Exceptions (v2.8.0)

Some advanced or niche mods legitimately make external connections or use elevated Java capabilities. A prime example is **Project Remnants**, which uses Java's HTTP client (`HttpClient.send`) to communicate with an external Large Language Model (LLM) server.

Instead of permanently turning off warnings or whitelisting mods by name (which malware could easily impersonate), PZ-ModGuard features **Cryptographic SHA-256 Exception Pinning**:

1. **Cryptographic Integrity**: When you approve a warning as trusted, PZ-ModGuard pins the exact SHA-256 cryptographic checksum of that container or class bytecode in `pzmg_exceptions.json`.
2. **Automatic Invalidation on Update**: As long as the file's SHA-256 hash remains unchanged, warnings are suppressed and marked `[USER EXCEPTION] (SHA-256 verified)`. If the mod author publishes an update on Steam Workshop, or if any byte in the file is modified or tampered with, the exception **automatically expires**, and PZ-ModGuard alerts you with an expiration notice.
3. **Interactive 1-Click Prompt**: If any interactive scan detects warnings, PZ-ModGuard asks:
   ```
   Would you like to save any detected warning(s) as a trusted SHA-256 exception? [Y/N]
   ```
   Selecting `Y` lets you approve the warning in a single keystroke.
4. **Dedicated Management Menu `[8]`**: From the main menu, press `[8]` at any time to:
   - List all active exceptions with target names, class entries, API patterns, and SHA-256 hashes.
   - Manually exempt a file by entering its path or dragging-and-dropping it into the window.
   - Remove individual exceptions or clear all.
5. **Tier 1 Critical Safeguard**: To prevent accidental bypasses of real threats, wildcard `pattern = "*"` exceptions will **never** suppress a Tier 1 Critical threat (Discord webhooks, reverse shells, token stealers).

Stored location:
- **Windows**: `%LOCALAPPDATA%\PZ-ModGuard\pzmg_exceptions.json`
- **Linux / SteamOS**: `~/.local/share/pz-modguard/pzmg_exceptions.json`
- **Portable**: Automatically checks `./pzmg_exceptions.json` in the scanner's folder.

---

## 💬 Community & Discord

Have questions, feedback, or want to discuss Project Zomboid Java modding security?
Join our community on Discord:

👉 **[Join our Discord Server](https://discord.gg/5rmsnwMPez)**

---

## 🤝 Contributing & False Positives

If a legitimate mod triggers a false positive notice, please [open an issue](https://github.com/KodeMannn/PZ-ModGuard/issues) or reach out on [Discord](https://discord.gg/5rmsnwMPez) with:
1. The Mod Name and Steam Workshop ID.
2. The relevant lines from your `pz_mod_scan_report.txt`.

Pull requests to improve detection heuristics or performance are welcome!

---

## 📄 License

Distributed under the [MIT License](LICENSE). Copyright (c) 2026 KodeMannn.
