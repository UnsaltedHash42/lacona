# Contributing

## Reporting New Findings

If you discover a novel DLL sideload that Lacuna doesn't detect, please open an
issue or PR with:

1. Application name and version
2. DLL name and export count
3. Path (user-writable vs Program Files)
4. Whether it's on hijacklibs.net
5. Load trigger (startup, specific feature, etc.)

## Code Contributions

### Setup

```bash
git clone https://github.com/UnsaltedHash42/lacona.git
cd lacuna
pip install -e ".[dev]"
```

### Code style

- Ruff for linting/formatting (config in `pyproject.toml`)
- Type hints on public functions
- Docstrings on modules and non-obvious functions

```bash
ruff check lacuna/
ruff format lacuna/
```

### Testing

```bash
pytest
```

Tests that need Windows or mingw are marked with `@pytest.mark.skipif`.

### Adding a new module

1. Create `lacuna/modules/your_module.py`
2. Add a CLI subcommand in `lacuna/cli.py` if user-facing
3. Add any new models to `lacuna/models.py`
4. Write at least one test

### Updating the KnownDLLs list

The bundled KnownDLLs list is in `lacuna/data/known_dlls_win11.txt`. To update:

```powershell
# On a Windows 11 machine:
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs" | 
    ForEach-Object { ($_ -split '\s+')[-1] } | 
    Where-Object { $_ -match '\.dll$' } |
    Sort-Object > known_dlls_win11.txt
```

### Updating hijacklibs data

The bundled snapshot in `hijacklibs.py` covers the most common entries.
For a full dataset:

```bash
git clone https://github.com/wietze/HijackLibs.git
# Point Lacuna at the data:
export HIJACKLIBS_DATA_DIR=/path/to/HijackLibs/yml
```

## Architecture Notes

### Cross-platform design

The core value prop is that scanning works on macOS/Linux against PE files.
New modules should preserve this where possible:

- `static_analyzer.py` — must stay cross-platform
- `proxy_generator.py` — must stay cross-platform
- `canary.py` — compile cross-platform, deploy Windows-only
- `dynamic_monitor.py` — Windows-only (OK)
- `windows_enumeration.py` — Windows-only (OK)

### Data flow

```
scan → [HijackCandidate] → novelty_check → proxy_generator → canary → validate
```

Each step is independently useful. The agent (`hunt` mode) orchestrates the full
pipeline, but each module works standalone via the CLI.
