# PZ-ModGuard 🛡️
**Advanced Java & Binary Mod Security Guard for Project Zomboid (Build 42)**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Discord](https://img.shields.io/badge/Discord-Join%20Community-5865F2?logo=discord&logoColor=white)](https://discord.gg/5rmsnwMPez)
[![Platform](https://img.shields.io/badge/Platform-Windows-blue.svg)](https://www.microsoft.com/windows)
[![Game](https://img.shields.io/badge/Project%20Zomboid-Build%2042-darkgreen.svg)](https://projectzomboid.com/)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero-brightgreen.svg)]()

**PZ-ModGuard** is a fast, standalone, pre-launch security scanner engineered to protect Project Zomboid players from malicious Java mods, trojan droppers, and credential stealers. 

Starting in Build 42, Project Zomboid mods can execute compiled Java bytecode (`.jar` / `.class`) and native agents. Because traditional antivirus programs (like Windows Defender) scan Windows `.exe`/`.dll` binaries and are mostly blind to Java bytecode constant pools, **PZ-ModGuard** fills the gap with an in-memory JVM Constant Pool parser and heuristic threat detection engine.

---

## ⚡ Quick Start

1. **Download**: Grab [`PZ-ModGuard.bat`](https://github.com/KodeMannn/PZ-ModGuard/releases/latest) or clone this repo.
2. **Run**: Double-click `PZ-ModGuard.bat` anywhere on your computer (desktop, workshop folder, or downloads).
3. **Choose Profile**: Press **[ENTER]** for the default **Quick Scan** (~1.5s), or select **[2] Full Deep Scan** to include the core game engine.
4. **Play Safe**: Review the color-coded report before launching Project Zomboid.

> **Zero Dependencies:** Requires no Python, no Node.js, and no external tools. Runs out-of-the-box on Windows 10 & 11 via native PowerShell-Batch polyglot.

---

## 🚀 Scan Profiles

PZ-ModGuard features 4 selectable scan modes to fit your workflow:

| Profile | Target Coverage | Typical Duration | Best For |
| :--- | :--- | :--- | :--- |
| **`[1] Quick Scan`** *(Default)* | Steam Workshop mods, Local user mods, Launcher config | **~1.5 seconds** | Daily check after subscribing to new mods |
| **`[2] Full Deep Scan`** | Base engine (`projectzomboid.jar`), Workshop, Loose overrides, Game root | **~6 seconds** | Initial setup or after installing engine-level mods |
| **`[3] Base Engine Only`** | Dedicated `projectzomboid.jar` integrity audit & Game Root | **~4.5 seconds** | Verifying game engine integrity without scanning mods |
| **`[4] Custom Target`** | Any specific mod folder or `.jar` file (supports drag-and-drop) | **< 1 second** | Testing an individual mod from NexusMods/Discord |

---

## 🔍 Key Features

* **⚡ Ultra-Fast Stream Engine:** Highly optimized stream reader processes thousands of compiled classes per second, completing full scans in seconds.
* **🎮 Deep Base Engine Audit (`projectzomboid.jar`):** Audits all 23,800+ core game engine classes for trojans and backdoors without triggering false alarms on official engine code, while identifying 3rd-party injected mod packages (such as ZombieBuddy).
* **🌐 Multi-Target Auto-Detection:** Automatically discovers and simultaneously scans across all:
  * **Steam Workshop Mods** (`steamapps/workshop/content/108600`) across all drives (`C:`, `D:`, `E:`, external NVMe SSDs).
  * **Main Game Directory** (`steamapps/common/ProjectZomboid`) to catch mods and DLLs installed directly into the game root.
  * **Local User Mods** (`%USERPROFILE%/Zomboid/mods`) for manually installed mods.
* **⚙️ Launcher JSON Integrity Check:** Inspects `ProjectZomboid64.json` to verify that JVM agent arguments (`-agentlib:`, `-agentpath:`, `-javaagent:`) only reference trusted agents (like `zbNative`).
* **🔬 High-Precision JVM Bytecode Parser:** Rather than naive byte-matching, PZ-ModGuard inspects the JVM class file format (`0xCAFEBABE`) in memory to extract true string literals, method descriptors, and class references.
* **🎯 3-Tier Threat Engine:**
  * **Tier 1 (CRITICAL - Red):** Active malicious payloads (Discord webhooks, Telegram bots, token grabbers, shell invocation like `cmd.exe`/`powershell.exe`, droppers like `curl`/`certutil`, and rogue `.exe`/`.dll`/`.vbs` files).
  * **Tier 2 (WARNING - Yellow):** Evasion and dropper patterns (in-memory classloaders like `ClassLoader.defineClass` used by modular trojans such as Fractureiser, string encryption ciphers like `javax.crypto.Cipher`, and raw TCP sockets).
  * **Tier 3 (CLEAN - Green):** Audited game reflection, rendering hooks, and math libraries.
* **🛡️ Anti-Tamper Scoped Whitelisting:** Requires triple-attribute matching `(ParentMod | ClassPath | Pattern)`. A malicious mod cannot evade detection simply by naming its class after a trusted mod.
* **📦 Full Surface Coverage:** Inspects `.jar` packages, loose `.class` overrides (such as *PZ_Optimization*), and native directory scripts.
* **📊 Visual UX & Progress Bar:** Profile selector menu, live ASCII percentage progress bar, Windows notification bar integration, and persistent terminal output.
* **📝 Automated Audit Logs:** Automatically saves a timestamped scan report to `pz_mod_scan_report.txt` for easy review or sharing.

---

## 🛡️ Threat Detection Matrix

| Threat Category | Example Signatures Detected | Severity |
| :--- | :--- | :--- |
| **Discord Webhooks / Exfiltration** | `discord.com/api/webhooks`, `discordapp.com/api/webhooks`, `api.telegram.org`, `pastebin.com/raw`, `iplogger`, `grabify` | **CRITICAL** |
| **Command Execution & Shells** | `cmd.exe`, `powershell.exe`, `wscript.exe`, `cscript.exe` | **CRITICAL** |
| **Payload Droppers** | `certutil`, `bitsadmin`, `curl.exe` | **CRITICAL** |
| **Info & Token Stealers** | `\AppData\Roaming\discord`, Chrome User Data, Firefox profiles | **CRITICAL** |
| **Persistence Mechanisms** | `\Microsoft\Windows\Start Menu\Programs\Startup` | **CRITICAL** |
| **Unauthorized Native Binaries** | Unwhitelisted `.exe`, `.dll`, `.vbs`, `.bat` files in mod directories | **CRITICAL** |
| **In-Memory Droppers (Fractureiser)** | `ClassLoader.defineClass`, `URLClassLoader` | **WARNING** |
| **Obfuscated Ciphers / Encryption** | `javax/crypto/Cipher`, `SecretKeySpec` | **WARNING** |
| **Raw Network Sockets** | `java/net/Socket`, `java/net/ServerSocket` | **WARNING** |

---

## ℹ️ Pre-Audited Benign Mods

The following mods have been inspected and whitelisted for specific framework operations:
* **ZombieBuddy** (`3619862853` & `3807686870`): Uses ByteBuddy agent attachment (`ProcessBuilder`) and bundled cryptography libraries (`org.bouncycastle.*`).
* **Viewpoint** (`3809306528`): Uses `ProcessBuilder` in `GpuBusy.class` solely to query Windows native `typeperf.exe` for GPU utilization statistics.
* **PZ_Optimization** (`3805285544`): In-game settings menu buttons use helper calls to `powershell.exe` for game restart and backup restoration.

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
