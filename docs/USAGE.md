# Usage Guide

## Overview

Lacuna has five main commands:

| Command | Purpose | Platform |
|---------|---------|----------|
| `scan` | Find DLL sideload candidates in PE files | Any |
| `proxy` | Generate proxy DLL source code | Any |
| `canary` | Build minimal test DLLs | Any (deploy: Windows) |
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

### Understanding scan output

The scanner reports **hijack candidates** — DLLs that could be sideloaded:

- **search_order**: DLL exists in the app directory AND is imported by an EXE in that directory. Attacker can replace it with a proxy.
- **phantom**: DLL is imported but doesn't exist in the app directory OR System32. Attacker can plant it directly (no rename needed).

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
