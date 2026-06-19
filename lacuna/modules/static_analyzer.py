"""Static PE analysis — enumerate imports, flag hijack candidates.

Works cross-platform via pefile. No Windows APIs needed.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

import pefile

from lacuna.models import (
    CandidateStatus,
    HijackCandidate,
    HijackType,
    TargetBinary,
)

log = logging.getLogger(__name__)

KNOWN_DLLS_DEFAULT: set[str] = {
    "advapi32.dll", "clbcatq.dll", "combase.dll", "comdlg32.dll",
    "coml2.dll", "difxapi.dll", "gdi32.dll", "gdiplus.dll",
    "iertutil.dll", "imagehlp.dll", "imm32.dll", "kernel32.dll",
    "lz32.dll", "msctf.dll", "msi.dll", "msvcrt.dll",
    "normaliz.dll", "nsi.dll", "ntdll.dll", "ole32.dll",
    "oleaut32.dll", "psapi.dll", "rpcrt4.dll", "sechost.dll",
    "setupapi.dll", "shell32.dll", "shcore.dll", "shlwapi.dll",
    "user32.dll", "version.dll", "wldap32.dll", "wow64.dll",
    "wow64win.dll", "ws2_32.dll", "ucrtbase.dll",
    "kernel32.dll", "kernelbase.dll", "ntdll.dll",
    "api-ms-win-crt-runtime-l1-1-0.dll",
    "api-ms-win-crt-heap-l1-1-0.dll",
    "api-ms-win-crt-string-l1-1-0.dll",
    "api-ms-win-crt-stdio-l1-1-0.dll",
    "api-ms-win-crt-math-l1-1-0.dll",
    "api-ms-win-crt-locale-l1-1-0.dll",
    "api-ms-win-crt-convert-l1-1-0.dll",
    "api-ms-win-crt-time-l1-1-0.dll",
    "api-ms-win-crt-filesystem-l1-1-0.dll",
    "api-ms-win-crt-environment-l1-1-0.dll",
    "api-ms-win-crt-process-l1-1-0.dll",
    "api-ms-win-crt-utility-l1-1-0.dll",
    "api-ms-win-core-synch-l1-2-0.dll",
}


def get_pe_imports(pe_path: Path) -> list[str]:
    """Extract imported DLL names from a PE file."""
    try:
        pe = pefile.PE(str(pe_path), fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
        )
    except pefile.PEFormatError:
        log.warning("Not a valid PE: %s", pe_path)
        return []

    dlls = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            name = entry.dll.decode("utf-8", errors="replace").lower()
            dlls.append(name)
    pe.close()
    return dlls


def get_pe_delay_imports(pe_path: Path) -> list[str]:
    """Extract delay-loaded DLL names from a PE file."""
    try:
        pe = pefile.PE(str(pe_path), fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"]]
        )
    except pefile.PEFormatError:
        return []

    dlls = []
    if hasattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
            name = entry.dll.decode("utf-8", errors="replace").lower()
            dlls.append(name)
    pe.close()
    return dlls


DLL_NAME_PATTERN = re.compile(rb"([a-zA-Z0-9_\-]+\.dll)\x00", re.IGNORECASE)


def get_pe_loadlibrary_strings(pe_path: Path) -> list[str]:
    """Extract DLL names referenced as strings (potential LoadLibrary targets)."""
    try:
        pe = pefile.PE(str(pe_path), fast_load=True)
    except pefile.PEFormatError:
        return []

    dlls = set()
    for section in pe.sections:
        data = section.get_data()
        for match in DLL_NAME_PATTERN.finditer(data):
            dll_name = match.group(1).decode("utf-8", errors="replace").lower()
            if len(dll_name) > 4 and not dll_name.startswith("api-ms-"):
                dlls.add(dll_name)

    pe.close()
    return list(dlls)


def get_pe_arch(pe_path: Path) -> str:
    """Return 'x86' or 'x64' based on PE machine type."""
    try:
        pe = pefile.PE(str(pe_path), fast_load=True)
        machine = pe.FILE_HEADER.Machine
        pe.close()
        if machine == 0x8664:
            return "x64"
        elif machine == 0x14C:
            return "x86"
        elif machine == 0xAA64:
            return "arm64"
        return "unknown"
    except pefile.PEFormatError:
        return "unknown"


def get_pe_signer(pe_path: Path) -> str | None:
    """Extract signer from PE's Authenticode signature (basic check)."""
    try:
        pe = pefile.PE(str(pe_path), fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
        )
        if hasattr(pe, "DIRECTORY_ENTRY_SECURITY"):
            # Has a signature — full verification needs Windows CryptoAPI
            # For now just flag as signed; detailed signer extraction on Windows
            pe.close()
            return "__signed__"
        pe.close()
        return None
    except (pefile.PEFormatError, Exception):
        return None


def get_dll_export_count(dll_path: Path) -> int:
    """Count exports in a DLL — fewer exports = easier proxy."""
    try:
        pe = pefile.PE(str(dll_path), fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
        )
        count = 0
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            count = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
        pe.close()
        return count
    except (pefile.PEFormatError, Exception):
        return -1


def analyze_binary(
    pe_path: Path,
    known_dlls: set[str] | None = None,
    system32_contents: set[str] | None = None,
) -> list[HijackCandidate]:
    """Analyze a single PE and return hijack candidates."""
    if known_dlls is None:
        known_dlls = KNOWN_DLLS_DEFAULT

    target = TargetBinary(
        path=pe_path,
        name=pe_path.name,
        arch=get_pe_arch(pe_path),
    )

    signer = get_pe_signer(pe_path)
    if signer:
        target.is_signed = True
        target.signer = signer

    imports = get_pe_imports(pe_path)
    target.imports = imports

    candidates = []
    seen_dlls: set[str] = set()

    # Standard imports
    for dll_name in imports:
        dll_lower = dll_name.lower()

        is_known = dll_lower in known_dlls or dll_lower.startswith("api-ms-win-")
        if is_known:
            continue

        hijack_type = HijackType.SEARCH_ORDER
        if system32_contents and dll_lower not in system32_contents:
            hijack_type = HijackType.PHANTOM

        candidate = HijackCandidate(
            target=target,
            dll_name=dll_name,
            hijack_type=hijack_type,
            status=CandidateStatus.DISCOVERED,
            is_known_dll=False,
            discovery_method="import_table",
        )
        candidates.append(candidate)
        seen_dlls.add(dll_lower)

    # Delay-load imports
    delay_imports = get_pe_delay_imports(pe_path)
    for dll_name in delay_imports:
        dll_lower = dll_name.lower()
        if dll_lower in known_dlls or dll_lower.startswith("api-ms-win-"):
            continue
        if dll_lower in seen_dlls:
            continue

        hijack_type = HijackType.DELAY_LOAD
        if system32_contents and dll_lower not in system32_contents:
            hijack_type = HijackType.PHANTOM

        candidate = HijackCandidate(
            target=target,
            dll_name=dll_name,
            hijack_type=hijack_type,
            status=CandidateStatus.DISCOVERED,
            is_known_dll=False,
            discovery_method="delay_import",
        )
        candidates.append(candidate)
        seen_dlls.add(dll_lower)

    # LoadLibrary string references
    runtime_dlls = get_pe_loadlibrary_strings(pe_path)
    for dll_name in runtime_dlls:
        dll_lower = dll_name.lower()
        if dll_lower in known_dlls or dll_lower.startswith("api-ms-win-"):
            continue
        if dll_lower in seen_dlls:
            continue

        candidate = HijackCandidate(
            target=target,
            dll_name=dll_name,
            hijack_type=HijackType.RUNTIME_LOAD,
            status=CandidateStatus.DISCOVERED,
            is_known_dll=False,
            discovery_method="string_ref",
            confidence="medium",
        )
        candidates.append(candidate)
        seen_dlls.add(dll_lower)

    return candidates


def scan_directory(
    directory: Path,
    known_dlls: set[str] | None = None,
    system32_contents: set[str] | None = None,
    recursive: bool = True,
) -> list[HijackCandidate]:
    """Scan all PEs in a directory tree."""
    pattern = "**/*.exe" if recursive else "*.exe"
    all_candidates = []

    for exe_path in directory.glob(pattern):
        try:
            candidates = analyze_binary(exe_path, known_dlls, system32_contents)
            all_candidates.extend(candidates)
            if candidates:
                log.info("%s: %d candidates", exe_path.name, len(candidates))
        except Exception as e:
            log.error("Failed to analyze %s: %s", exe_path, e)

    return all_candidates
