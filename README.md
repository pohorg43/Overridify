# Overridify

<p align="left">
  <strong>🌐 Language / Язык:</strong>
  <b>English</b> | <a href="README.ru.md">Русский</a>
</p>

**Low-level Ground Truth audit and selective override engine for Android system properties.**

Unlike conventional tweakers built around blind copy-pasted property lists from the internet, **Overridify** operates on the **Ground Truth** principle. It ships with a custom native C micro-scanner (`overridify-scan`) and a multi-threaded Dalvik DEX analyzer that disassemble ARM64 system binaries/libraries and parse framework/APK bytecode directly on the device — proving whether a flag is genuinely read by your ROM's machine code, what its true compile-time default is, or whether it is complete dead weight.

Alongside the audit engine, Overridify includes an intelligent preset manager: verified hardware-aware profiles, an interactive custom profile builder with real-time ROM validation, and instant `OVRD1` Base64 preset/pack sharing.

---

## Key Features

- **Exact Property Provenance (Source Detection)** — identifies the real author of every flag and override in the live system: compiled into ROM code, declared in partition `build.prop`, set by `init` (`*.rc`) services, stored in `/data/property` (`persist`), or injected by a specific installed Magisk / KernelSU / APatch module.
- **Junk Radar & Module Auditor** — scans active system properties and exposes placebo "optimizer" modules by catching:
  - Cross-platform leftovers (e.g., MediaTek flags injected on Snapdragon devices, and vice versa);
  - Deprecated AOSP flags with exact Android lifecycle removal info (e.g., `deprecated A11+`);
  - Typos and mythical tweaker flags that never existed in Android binaries.
- **Compile-Time Machine Defaults (>80% Precision)** — extracts true factory default values compiled directly into native ARM64 libraries (`.rodata`, `.data.rel.ro` tables, function prologues) and Dalvik DEX bytecode (`<clinit>` / `SystemProperties.get*`).
- **Smart Preset Manager & Profile Builder** —
  - Built-in profiles (*Vulkan UI Pipeline*, *SurfaceFlinger Vulkan*, *Ultra Smooth UI*, *Touch Response*, *Gaming Mode*) with conflict detection against installed modules;
  - **Mali Guard & Qualcomm Guard** — automatic ARM64 binary patcher for the Mali Vulkan `vkGetDeviceQueue2` driver defect (prevents SurfaceFlinger black screen/hang) and anti-flicker protection for Snapdragon;
  - Interactive custom preset constructor (`key=value`) with instant scanner validation against your ROM's binaries;
  - Fast export & import of single presets or full packs via compact `OVRD1:` strings.
- **100% Offline & Self-Contained** — zero internet access, zero external dependencies (`pkg install` is not required). Bundles an embedded `mawk` engine and native C binaries.
- **Bilingual TUI & CLI** — full English and Russian interface.

---

## Reading Audit Results

Every audited property is presented as a detailed diagnostic card:

```text
* debug.hwui.renderer
    Value    : [unset]
    Source   : aosp
    Scanner  : DEFAULT_STR: "skiagl"
```

### 1. What `Source` means
Shows where the operating system actually obtains the property's value:

| Source | Meaning |
| :--- | :--- |
| **`aosp`** | Standard pure Android flag. When `[unset]`, the OS uses the verified AOSP reference default. |
| **`qti (caf)`** | Verified Qualcomm Snapdragon (CAF / QTI) platform property. |
| **`vendor (rom)`** | Firmware compile-time default: the number, boolean, or string is hardcoded directly into the binary by the compiler. |
| **`unverified`** | Property is `[unset]` in the live system and its default is computed dynamically at runtime (not yet in the static reference DB). |
| **`<partition> (build.prop)`** | Explicitly defined in partition prop files (`/system`, `/vendor`, `/odm`, `/product`, `/system_ext`). |
| **`module (<name>)`** | Overridden by a specific installed Magisk / KernelSU / APatch module. |
| **`service (<name.rc>)`** | Set dynamically by an Android `init` script (`*.rc`) during boot. |
| **`persist (/data)`** | Stored persistently in `/data/property`. |

### 2. What `Scanner` Verdicts mean
Result of static ARM64 machine code disassembly and Dalvik DEX bytecode inspection:

| Verdict | Meaning |
| :--- | :--- |
| **`DEFAULT_BOOL (true/false)`** | Resolved boolean compile-time default. |
| **`DEFAULT_INT: <number>`** | Resolved integer compile-time default. |
| **`DEFAULT_STR: "<text>"`** | Resolved string compile-time default. |
| **`DYNAMIC_DEFAULT`** | Binary genuinely reads the property, but its fallback value is computed dynamically at runtime. |
| **`NOT_FOUND_IN_BINARY`** | Property is present in `getprop`, but no reader exists in the target binary (or it is an unread legacy leftover). |

---

## Interface & CLI Usage

### Interactive TUI (in Termux)
The installer automatically creates a Termux shortcut — no manual `su` switch needed:

```bash
overridify
# or classically:
su -c overridify
```

### Quick CLI Commands

```bash
overridify audit [sub|full]   # Subsystem audit or full system audit across all ROM binaries/JARs
overridify radar              # Scan live system and installed modules for placebo/junk flags
overridify preset [cmd]       # Manage presets (status / apply / reset / export / import OVRD1)
overridify search <query>     # Search properties across system ELF binaries and DEX framework
overridify export [path]      # Export full detailed audit report (default: /sdcard/...)
overridify help               # Show CLI command reference
```

---

## System Requirements

- **Architecture:** ARM64 (`aarch64`)
- **Android Version:** Android 6.0 Marshmallow+ (**API 23+**) *(Android 8.0+ / API 26+ recommended for full Treble `/vendor` & `/odm` partition separation)*
- **Root Solution:** Magisk 20.4+, KernelSU (and forks), or APatch
- **Terminal:** [Termux](https://github.com/termux/termux-app)

---

## Installation

1. Download the latest flashable `Overridify-v*.zip` from [**Releases**](../../releases).
2. Flash it via Magisk / KernelSU / APatch manager *(available immediately in Termux; reboot only required after applying property presets)*.
3. Open Termux and run `overridify`.

---

## Building from Source

Native ARM64 binaries (`overridify-scan` and `mali-patcher`) are compiled automatically from [`src/`](src/) via [GitHub Actions CI](.github/workflows/build.yml) using Android NDK targeting **API 23 (`aarch64-linux-android23-clang`)**.

To build manually:

```bash
# On device in Termux:
clang -O3 -Wall src/overridify-scan.c -lz -lpthread -o bin/overridify-scan
clang -O3 -Wall src/mali-patcher.c -o bin/mali-patcher

# Cross-compiling on Linux x86_64 with Android NDK (API 23+):
$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android23-clang \
    -O3 -Wall -s src/overridify-scan.c -lz -o bin/overridify-scan
$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android23-clang \
    -O3 -Wall -s src/mali-patcher.c -o bin/mali-patcher
```

## Project Structure

```text
overridify/
├── module.prop                  # Module metadata
├── customize.sh                 # Installer (preserves user overrides & custom presets on upgrade)
├── uninstall.sh                 # Clean removal handler
├── skip_mount / skip_mountify   # Overlay isolation markers
├── bin/
│   ├── overridify               # Main TUI/CLI engine (Shell + AWK orchestration)
│   ├── overridify-scan*         # Native ARM64 ELF disassembler & DEX scanner (built in CI)
│   ├── mali-patcher*            # Native ARM64 Mali GPU driver patcher (built in CI)
│   └── mawk                     # Embedded standalone AWK engine
├── src/
│   ├── overridify-scan.c        # ARM64 static analyzer & Dalvik DEX parser (C)
│   └── mali-patcher.c           # vkGetDeviceQueue2 binary patcher (C)
├── common/
│   ├── database/                # AOSP lifecycle DB, subsystem targets & preset definitions
│   └── languages/ru.sh          # Russian localization
└── .github/workflows/build.yml  # Automated NDK build & release ZIP packaging
```

> `*` Compiled automatically by GitHub Actions CI from `src/` and packaged into release archives.

---

## License & Links

- **License:** [GNU General Public License v3.0](LICENSE)
- **Author:** **[@pohorg](https://t.me/pohorg)** (Telegram)
- **Community & Discussion (4PDA):** [Overridify on 4PDA](https://4pda.to/forum/index.php?showtopic=915158&view=findpost&p=145907205)
