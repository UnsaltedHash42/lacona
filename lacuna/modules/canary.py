"""Canary DLL generation and testing.

Compiles minimal DLLs that write a breadcrumb on DLL_PROCESS_ATTACH
to confirm a hijack candidate actually loads from the plant path.
"""

from __future__ import annotations

import logging
import subprocess
import tempfile
import time
from pathlib import Path

log = logging.getLogger(__name__)

CANARY_SOURCE_TEMPLATE = r"""// Lacuna canary DLL — {dll_name}
// Writes breadcrumb to confirm load from plant path
#include <windows.h>
#include <stdio.h>

{export_pragmas}

void WriteBreadcrumb(void) {{
    HANDLE hFile = CreateFileA(
        "{breadcrumb_path}",
        GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {{
        DWORD pid = GetCurrentProcessId();
        char buf[256];
        int len = wsprintfA(buf, "LACUNA_CANARY|dll=%s|pid=%lu|host={host_exe}\n",
                           "{dll_name}", pid);
        DWORD written;
        WriteFile(hFile, buf, len, &written, NULL);
        CloseHandle(hFile);
    }}
}}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {{
    if (dwReason == DLL_PROCESS_ATTACH) {{
        WriteBreadcrumb();
    }}
    return TRUE;
}}
"""

EXPORT_PRAGMA_TEMPLATE = '#pragma comment(linker, "/export:{name}={forward_dll}.{name},@{ordinal}")'

MINIMAL_EXPORT_SOURCE = r"""// Lacuna canary — minimal, no forwarding
#include <windows.h>

void WriteBreadcrumb(void) {{
    HANDLE hFile = CreateFileA(
        "{breadcrumb_path}",
        GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {{
        char buf[128];
        int len = wsprintfA(buf, "LACUNA_CANARY|dll={dll_name}|pid=%lu\n",
                           GetCurrentProcessId());
        DWORD written;
        WriteFile(hFile, buf, len, &written, NULL);
        CloseHandle(hFile);
    }}
}}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {{
    if (dwReason == DLL_PROCESS_ATTACH) {{
        WriteBreadcrumb();
    }}
    return TRUE;
}}
"""


def find_mingw_compiler(arch: str = "x64") -> Path | None:
    """Locate mingw cross-compiler."""
    if arch == "x64":
        names = ["x86_64-w64-mingw32-gcc"]
    else:
        names = ["i686-w64-mingw32-gcc"]

    for name in names:
        try:
            result = subprocess.run(
                ["which", name] if not Path("C:/").exists() else ["where", name],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                return Path(result.stdout.strip().split("\n")[0])
        except FileNotFoundError:
            continue

    # Try common Windows paths
    for p in [
        Path("C:/msys64/mingw64/bin/gcc.exe"),
        Path("C:/mingw64/bin/gcc.exe"),
    ]:
        if p.exists():
            return p

    return None


def generate_canary_source(
    dll_name: str,
    host_exe: str,
    breadcrumb_dir: Path,
    exports: list[dict] | None = None,
    forward_dll: str | None = None,
) -> str:
    """Generate canary DLL C source.

    Args:
        dll_name: Name of the DLL to impersonate
        host_exe: Name of the host executable
        breadcrumb_dir: Directory to write breadcrumb file
        exports: List of {name, ordinal} to forward (optional)
        forward_dll: DLL to forward exports to (renamed original)
    """
    breadcrumb_path = str(breadcrumb_dir / f"lacuna_{dll_name}.breadcrumb").replace("\\", "\\\\")

    if exports and forward_dll:
        pragmas = []
        for exp in exports:
            pragma = EXPORT_PRAGMA_TEMPLATE.format(
                name=exp["name"],
                forward_dll=forward_dll.replace(".dll", ""),
                ordinal=exp.get("ordinal", 1),
            )
            pragmas.append(pragma)
        export_pragmas = "\n".join(pragmas)

        return CANARY_SOURCE_TEMPLATE.format(
            dll_name=dll_name,
            host_exe=host_exe,
            breadcrumb_path=breadcrumb_path,
            export_pragmas=export_pragmas,
        )
    else:
        return MINIMAL_EXPORT_SOURCE.format(
            dll_name=dll_name,
            breadcrumb_path=breadcrumb_path,
        )


def compile_canary(
    source: str,
    output_path: Path,
    arch: str = "x64",
    compiler: Path | None = None,
) -> bool:
    """Compile canary DLL from source string.

    Returns True on success.
    """
    if compiler is None:
        compiler = find_mingw_compiler(arch)
        if compiler is None:
            log.error("No mingw compiler found for %s", arch)
            return False

    with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
        f.write(source)
        source_path = Path(f.name)

    try:
        cmd = [
            str(compiler),
            "-shared",
            "-o", str(output_path),
            str(source_path),
            "-lkernel32",
            "-nostdlib",
            "-Wl,--entry,DllMain",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            # Try with standard lib (some DLLs need CRT)
            cmd_crt = [
                str(compiler),
                "-shared",
                "-o", str(output_path),
                str(source_path),
            ]
            result = subprocess.run(cmd_crt, capture_output=True, text=True, timeout=30)

        if result.returncode == 0:
            log.info("Compiled canary: %s", output_path)
            return True
        else:
            log.error("Compilation failed: %s", result.stderr)
            return False
    finally:
        source_path.unlink(missing_ok=True)


def deploy_canary(
    canary_dll: Path,
    plant_path: Path,
    dll_name: str,
) -> Path:
    """Copy canary DLL to the plant location."""
    destination = plant_path / dll_name
    import shutil
    shutil.copy2(canary_dll, destination)
    log.info("Deployed canary: %s", destination)
    return destination


def check_breadcrumb(
    breadcrumb_dir: Path,
    dll_name: str,
    timeout_seconds: int = 5,
) -> dict | None:
    """Check if canary breadcrumb was written.

    Returns parsed breadcrumb data or None.
    """
    breadcrumb_file = breadcrumb_dir / f"lacuna_{dll_name}.breadcrumb"

    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        if breadcrumb_file.exists():
            content = breadcrumb_file.read_text().strip()
            parts = dict(kv.split("=", 1) for kv in content.split("|")[1:] if "=" in kv)
            log.info("CANARY HIT: %s — %s", dll_name, parts)
            return parts
        time.sleep(0.5)

    return None


def cleanup_canary(plant_path: Path, dll_name: str, breadcrumb_dir: Path):
    """Remove deployed canary and breadcrumb."""
    canary = plant_path / dll_name
    breadcrumb = breadcrumb_dir / f"lacuna_{dll_name}.breadcrumb"
    canary.unlink(missing_ok=True)
    breadcrumb.unlink(missing_ok=True)
