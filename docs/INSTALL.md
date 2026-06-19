# Installation

## Quick Start

```bash
git clone https://github.com/your-org/lacuna.git
cd lacuna
pip install -e .
```

## Requirements

### Core (scanning and proxy generation)
- Python 3.10 or later
- `pefile` — PE format parsing (auto-installed)
- `rich` — terminal output formatting (auto-installed)

These are sufficient for `lacuna scan` and `lacuna proxy` on any platform.

### Cross-compilation (building proxy DLLs from macOS/Linux)
- `mingw-w64` — x86_64 Windows cross-compiler

```bash
# macOS
brew install mingw-w64

# Ubuntu/Debian
apt install mingw-w64

# Fedora
dnf install mingw64-gcc

# Arch
pacman -S mingw-w64-gcc
```

After installation, verify:
```bash
x86_64-w64-mingw32-gcc --version
```

### Windows-native compilation
On Windows, you can use:
- MinGW-w64 via [MSYS2](https://www.msys2.org/)
- Visual Studio Developer Command Prompt (`cl.exe`)
- Or any GCC/MSVC that targets x86_64 Windows

### Agentic hunt mode (optional)
- `anthropic` Python SDK (auto-installed)
- `ANTHROPIC_API_KEY` environment variable set
- Windows environment (agent needs to interact with running software)

### Dynamic monitoring (optional, Windows only)
- Process Monitor (Procmon64.exe) from Sysinternals
- `pywin32` — Windows API bindings

```bash
pip install -e ".[windows]"
```

## Platform Support

| Feature | macOS/Linux | Windows |
|---------|-------------|---------|
| `lacuna scan` | Yes | Yes |
| `lacuna proxy` | Yes | Yes |
| `lacuna canary` (compile) | Yes (cross-compile) | Yes |
| `lacuna canary` (deploy+test) | No | Yes |
| `lacuna dynamic` | No | Yes |
| `lacuna hunt` | Partial (scan only) | Yes |

## Verifying Installation

```bash
# Should show help
lacuna --help

# Should analyze a PE file (if you have one)
lacuna scan /path/to/some.exe

# Should show suggestions
lacuna suggest
```

## Development Setup

```bash
pip install -e ".[dev]"

# Run tests
pytest

# Lint
ruff check lacuna/
```
