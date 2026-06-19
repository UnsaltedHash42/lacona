# Usage Guide

## Overview

Lacuna has six main commands:

| Command | Purpose | Platform |
|---------|---------|----------|
| `scan` | Find DLL sideload candidates in PE files | Any |
| `proxy` | Generate proxy DLL source code | Any |
| `canary` | Build minimal test DLLs | Any (deploy: Windows) |
| `validate` | Remote validation of findings via WinRM/SSH | Any → Windows |
| `dynamic` | Runtime DLL load monitoring | Windows |
| `suggest` | List software worth scanning | Any |
| `hunt` | Autonomous discovery loop | Windows |

## Scanning

### Scan a directory

```bash
# Scan all executables recursively
lacuna scan "C:\Users\you\AppData\Local"

# Scan a single application
lacuna scan "C:\Users\you\AppData\Local\Discord"

# Scan exported PE files on macOS
lacuna scan ./windows-binaries/
```

### Scoring and filtering

```bash
# Score candidates (default — sorted by operability score)
lacuna scan ./windows-binaries/ --score

# Only show high-value targets
lacuna scan ./windows-binaries/ --min-score 50

# Disable scoring (raw alphabetical output)
lacuna scan ./windows-binaries/ --no-score

# JSON output (includes score + breakdown)
lacuna scan ./windows-binaries/ --format json

# Write JSON to output directory
lacuna scan ./windows-binaries/ --format json -o ./results/
```

Scoring factors: path writability (+30), auto-start trigger (+25), SYSTEM context (+20), novelty (+15), phantom DLL (+15), low exports (+10), delay-load (+10), signed host (+10), universal proxy potential (+10).

### Understanding scan output

The scanner reports **hijack candidates** — DLLs that could be sideloaded:

- **search_order**: DLL exists in the app directory AND is imported by an EXE in that directory. Attacker can replace it with a proxy.
- **phantom**: DLL is imported but doesn't exist in the app directory OR System32. Attacker can plant it directly (no rename needed).
- **delay_load**: DLL is in the PE delay-import directory. Loads later (on first API call), meaning the app is stable when the proxy activates.
- **runtime_load**: DLL name found as a string in PE sections (likely `LoadLibrary` target). Not in any import directory.

Discovery methods shown in output:
- `import_table` — standard PE import directory
- `delay_import` — PE delay-import directory
- `string_ref` — extracted from PE section strings (confidence: medium)

### Filtering results

The scanner automatically excludes:
- **KnownDLLs** — kernel-cached DLLs that Windows loads from a protected path regardless of search order
- **api-ms-win-*** — API set DLLs (virtual, resolved by the loader)
- **vcruntime/msvcp** — Visual C++ runtime (usually side-by-side)

Remaining candidates are checked against hijacklibs.net for novelty.

## Generating Proxy DLLs

```bash
lacuna proxy "C:\path\to\target\dxcompiler.dll"
```

This generates a complete project:

```
lacuna_output/proxies/dxcompiler/
├── dxcompiler_proxy.c     # C source with payload stub + export pragmas
├── dxcompiler_proxy.def   # Module definition file (for mingw)
├── build.cmd              # Build script
└── DEPLOY.txt             # Deployment instructions
```

### Custom forward name

By default, the proxy forwards to `<name>_orig.dll`. Override with:

```bash
lacuna proxy target.dll --forward-name "target_real.dll"
```

### Building the proxy

```bash
# MinGW (cross-compile from macOS/Linux)
x86_64-w64-mingw32-gcc -shared -o dxcompiler.dll dxcompiler_proxy.c dxcompiler_proxy.def

# MSVC (Windows)
cl /LD /Fe:dxcompiler.dll dxcompiler_proxy.c /link /DEF:dxcompiler_proxy.def
```

### Deployment

1. In the target app directory, rename the original: `dxcompiler.dll` → `dxcompiler_orig.dll`
2. Place compiled proxy as `dxcompiler.dll`
3. Launch the application
4. The proxy forwards all exports to the original (app works normally)
5. Your payload fires in DllMain

## Canary Testing

A canary is a minimal DLL that writes a "breadcrumb" file on load — confirming
the sideload path works without needing a full payload.

```bash
# Compile a canary
lacuna canary dxcompiler.dll "C:\Users\you\AppData\Local\Programs\obsidian" \
    --host-exe Obsidian.exe --arch x64
```

This creates a DLL that, when loaded, writes evidence to a breadcrumb directory.
Deploy it to the target path and launch the host application.

### Checking results

```bash
# Look for the breadcrumb
dir lacuna_output\breadcrumbs\lacuna_dxcompiler.dll.breadcrumb
type lacuna_output\breadcrumbs\lacuna_dxcompiler.dll.breadcrumb
```

If the file exists, the hijack is confirmed.

## Dynamic Monitoring

Catch DLLs loaded at runtime that aren't visible in the static import table
(delay-loads, LoadLibrary calls, plugin loading):

```bash
lacuna dynamic "C:\Program Files\Zoom\bin\Zoom.exe" --duration 30
```

This runs Process Monitor, captures DLL load events, and reports "NAME NOT FOUND"
results — DLLs the app searched for but didn't find. These are phantom candidates.

Requires: Procmon64.exe on PATH or via `--procmon`.

## Target Suggestions

```bash
# All suggestions
lacuna suggest

# Filter by category
lacuna suggest --category rmm
lacuna suggest --category vpn
lacuna suggest --category conferencing

# Only targets that run as SYSTEM
lacuna suggest --system-only
```

Categories: `rmm`, `backup`, `vpn`, `conferencing`, `dev_tool`, `print`, `av`, `browser`

## Agentic Hunt Mode

The autonomous hunt loop uses Claude to orchestrate the full pipeline:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
lacuna hunt --context "scanning dev workstation, interested in electron apps and git tools" \
    --max-iter 50 \
    -o ./hunt_results/
```

The agent will:
1. Enumerate installed software
2. Identify high-value targets
3. Run static analysis
4. Generate and compile proxy DLLs
5. Deploy canaries and check results
6. Filter for novelty
7. Write a findings report

## Remote Validation

Validate scan findings against a remote Windows host over WinRM or SSH. This deploys canary DLLs, launches the target app, and checks for breadcrumb files — confirming real-world exploitation potential.

```bash
# Install remote transport dependencies
pip install lacuna[remote]

# Validate all findings
lacuna validate \
    --target 192.168.1.50 \
    --user Administrator \
    --password 'Lacuna-Research!' \
    --findings scan_results.json

# Validate only high-scoring findings
lacuna validate \
    --target 192.168.1.50 \
    --user Admin \
    --password '...' \
    --findings results.json \
    --filter-score 60

# SSH transport
lacuna validate \
    --target 10.0.0.5 \
    --user admin \
    --key ~/.ssh/lab_key \
    --transport ssh \
    --findings results.json

# Dry-run (show what would be validated without touching the remote)
lacuna validate \
    --target 10.0.0.5 \
    --user Admin \
    --password '...' \
    --findings results.json \
    --dry-run
```

### How it works

For each candidate in the findings JSON:
1. Compiles a canary DLL locally (mingw cross-compilation)
2. Uploads the canary to the remote host
3. Backs up the original DLL (`.lacuna_bak`)
4. Deploys canary in its place
5. Launches the host application
6. Polls for breadcrumb (confirms DLL was loaded)
7. Checks process survival (app didn't crash)
8. Kills the app and restores the original DLL
9. Verifies restoration via SHA256 hash

### Safety features

- Originals are always restored in a `finally` block
- SHA256 hash verification after restore
- 30s timeout per validation (configurable with `--timeout`)
- Dry-run mode to preview without executing
- Sequential execution by default (`--max-parallel 1`)

### Prerequisites

- `mingw-w64` for cross-compiling canary DLLs
- WinRM: target must have WinRM enabled (`winrm quickconfig`)
- SSH: target must have OpenSSH server installed

## Tips

### Getting PE files on macOS/Linux

If you don't have direct Windows access, you can still use Lacuna's scanner:

1. Mount a Windows partition or VM shared folder
2. Copy `%LOCALAPPDATA%` contents to your machine
3. Scan the copied directory — pefile works on raw PE files anywhere

### Prioritizing findings

Best candidates have:
- **Few exports** (2-10) — trivial to proxy
- **User-writable path** — no admin needed
- **Auto-start trigger** — payload fires without user action
- **Signed host EXE** — appears trusted to EDR
- **Novel** — not on hijacklibs.net

### The Electron shortcut

Almost every Electron app ships `dxcompiler.dll` (2 exports) and `ffmpeg.dll`
(50-73 exports) in its user-writable app directory. If your target runs ANY
Electron app, you likely have a sideload vector.
