# Lacuna — Automated DLL Sideload Discovery

## What this is

Tool that finds novel DLL sideloading/hijack opportunities in Windows software.
"Novel" means not already on hijacklibs.net or in public CVEs.

## Architecture

```
CLI (lacuna/cli.py)
 └─ Orchestrator (lacuna/orchestrator.py)
     ├─ Agent Loop (lacuna/agent.py) ← Claude API calls (optional)
     └─ Modules:
         ├─ static_analyzer.py   — PE import parsing via pefile (cross-platform)
         ├─ dynamic_monitor.py   — Procmon/ETW capture (Windows only)
         ├─ canary.py            — Compile/deploy test DLLs (needs mingw)
         ├─ proxy_generator.py   — Full proxy DLL source generation
         ├─ target_acquisition.py — Suggest/install software to scan
         ├─ windows_enumeration.py — Services, tasks, auto-runs, ACLs
         └─ hijacklibs.py        — Novelty filter against known DB
```

## Usage

```bash
# Install
pip install -e .

# One-shot static scan (works on macOS/Linux with PE files)
lacuna scan /path/to/program-files-export/

# Scan user-writable app directories
lacuna scan "%LOCALAPPDATA%"

# Full agentic hunt (needs Windows + API key)
ANTHROPIC_API_KEY=sk-... lacuna hunt --context "dev workstation with electron apps and git tools"

# Generate proxy for a specific DLL
lacuna proxy ./target/dxcompiler.dll

# Build and deploy canary
lacuna canary dxcompiler.dll ./target/ --host-exe App.exe

# Suggest targets
lacuna suggest --system-only
```

## Development

- Python 3.10+
- `pip install -e ".[dev]"` for test/lint deps
- Static analysis module works cross-platform (macOS/Linux/Windows)
- Dynamic/canary/enum modules need Windows
- Agent loop needs ANTHROPIC_API_KEY (optional — scan/proxy/canary work without it)
- Cross-compile canaries with `brew install mingw-w64` or `apt install mingw-w64`

## Key Design Decisions

- pefile for cross-platform PE parsing (no Windows APIs needed for discovery)
- .DEF file export forwarders over #pragma (works with mingw cross-compilation)
- Canary payload writes a file (not network) for validation without infrastructure
- KnownDLLs list is bundled (data/known_dlls_win11.txt) for offline use
- hijacklibs.net check uses bundled snapshot + optional live lookup
