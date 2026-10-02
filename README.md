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
3. **Confirm**: Press **[ENTER]** when prompted to initiate the scan.
4. **Play Safe**: Review the color-coded report before launching Project Zomboid.

> **Zero Dependencies:** Requires no Python, no Node.js, and no external tools. Runs out-of-the-box on Windows 10 & 11 via native PowerShell-Batch polyglot.

---

## 🔍 Key Features

* **🔬 High-Precision JVM Constant Pool Parser:** Rather than naive byte-matching (which triggers false positives on compiled opcodes), PZ-ModGuard binary-parses the JVM class file format (`0xCAFEBABE`) in memory to extract true `CONSTANT_Utf8` string literals, method descriptors, and class references.
* **🌐 Multi-Drive Steam Library Auto-Detection:** Automatically inspects the Windows Registry (`HKCU:\Software\Valve\Steam\SteamPath`) and parses Steam's `libraryfolders.vdf` to discover mods across all storage drives (`C:`, `D:`, `E:`, external NVMe SSDs).
* **🎯 3-Tier Threat Engine:**
  * **Tier 1 (CRITICAL - Red):** Active malicious payloads (Discord webhooks, Telegram bots, token grabbers, shell invocation like `cmd.exe`/`powershell.exe`, droppers like `curl`/`certutil`, and rogue `.exe`/`.dll`/`.vbs` files).
  * **Tier 2 (WARNING - Yellow):** Evasion and dropper patterns (in-memory classloaders like `ClassLoader.defineClass` used by modular trojans such as Fractureiser, string encryption ciphers like `javax.crypto.Cipher`, and raw TCP sockets).
  * **Tier 3 (CLEAN - Green):** Audited game reflection, rendering hooks, and math libraries.
* **🛡️ Anti-Tamper Scoped Whitelisting:** Requires triple-attribute matching `(ParentMod | ClassPath | Pattern)`. A malicious mod cannot evade detection simply by naming its class after a trusted mod.
* **📦 Full Surface Coverage:** Inspects `.jar` packages, loose `.class` overrides (such as *PZ_Optimization*), and native directory scripts.
* **📊 Visual UX & Progress Bar:** Interactive pre-scan confirmation prompt, dual-stage visual progress bars (for JAR archives and loose classes), and persistent terminal output.
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
