"""Interface to hijacklibs.net — filter out already-known hijacks.

The agent needs novel targets. This module checks candidates against
the public hijacklibs database to flag (not exclude) burned ones.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

log = logging.getLogger(__name__)

# Bundled snapshot of known hijacks — update periodically from
# https://github.com/wietze/HijackLibs/tree/master/_data
# Format: {dll_name_lower: [list of known vulnerable executables]}
KNOWN_HIJACKS_BUNDLED: dict[str, list[str]] = {
    "version.dll": ["teams.exe", "onedrive.exe", "code.exe", "msedge.exe"],
    "dbghelp.dll": ["windbg.exe", "devenv.exe"],
    "winmm.dll": ["mstsc.exe", "wordpad.exe"],
    "mswsock.dll": ["ftp.exe"],
    "uxtheme.dll": ["explorer.exe"],
    "dwmapi.dll": ["notepad++.exe"],
    "profapi.dll": ["whoami.exe"],
    "ntmarta.dll": ["searchprotocolhost.exe"],
    "wtsapi32.dll": ["calc.exe"],
    "userenv.dll": ["gpupdate.exe"],
    "cscapi.dll": ["explorer.exe"],
    "propsys.dll": ["explorer.exe"],
    "secur32.dll": ["control.exe"],
    "IPHLPAPI.DLL": ["tracert.exe"],
    "dwrite.dll": ["wordpad.exe", "mspaint.exe"],
    "msimg32.dll": ["mspaint.exe"],
    "TextShaping.dll": ["notepad.exe"],
    "edputil.dll": ["msedge.exe", "teams.exe"],
    "wer.dll": ["consent.exe"],
    "faultrep.dll": ["wermgr.exe"],
    "dbgcore.dll": ["werfault.exe"],
    "npmproxy.dll": ["mmc.exe"],
    "tapi32.dll": ["svchost.exe"],
    "netutils.dll": ["net.exe"],
    "credui.dll": ["runas.exe"],
    "cryptsp.dll": ["certutil.exe"],
}

# Path to local hijacklibs JSON data (cloned repo)
HIJACKLIBS_DATA_DIR: Path | None = None


def load_hijacklibs_data(data_dir: Path | None = None) -> dict[str, list[str]]:
    """Load full hijacklibs dataset from cloned repo or bundled data."""
    if data_dir and data_dir.exists():
        full_data = {}
        for yml_file in data_dir.glob("*.yml"):
            # Parse YAML entries — simplified since we want just dll+exe pairs
            content = yml_file.read_text()
            # Extract dll name from filename
            dll_name = yml_file.stem.lower() + ".dll"
            exes = []
            for line in content.split("\n"):
                if "executable:" in line.lower():
                    exe = line.split(":")[-1].strip().strip("'\"")
                    if exe:
                        exes.append(exe.lower())
            if exes:
                full_data[dll_name] = exes
        if full_data:
            return full_data

    return KNOWN_HIJACKS_BUNDLED


def is_known_hijack(dll_name: str, exe_name: str | None = None) -> bool:
    """Check if a DLL (optionally paired with an EXE) is already known."""
    data = load_hijacklibs_data(HIJACKLIBS_DATA_DIR)
    dll_lower = dll_name.lower()

    if dll_lower not in data:
        return False

    if exe_name is None:
        return True

    return exe_name.lower() in data[dll_lower]


def get_known_dlls_set() -> set[str]:
    """Get set of all DLL names known to hijacklibs."""
    data = load_hijacklibs_data(HIJACKLIBS_DATA_DIR)
    return set(data.keys())


def novelty_check(dll_name: str, exe_name: str) -> dict:
    """Comprehensive novelty assessment for a candidate.

    Returns:
        {is_novel: bool, reason: str, confidence: float}
    """
    data = load_hijacklibs_data(HIJACKLIBS_DATA_DIR)
    dll_lower = dll_name.lower()
    exe_lower = exe_name.lower()

    if dll_lower not in data:
        return {
            "is_novel": True,
            "reason": "DLL not in hijacklibs database at all",
            "confidence": 0.9,
        }

    known_exes = data[dll_lower]
    if exe_lower in known_exes:
        return {
            "is_novel": False,
            "reason": f"Known hijack: {dll_name} via {exe_name} — already in hijacklibs",
            "confidence": 1.0,
        }

    return {
        "is_novel": True,
        "reason": f"DLL is known-hijackable but not via this specific binary ({exe_name})",
        "confidence": 0.7,
    }
