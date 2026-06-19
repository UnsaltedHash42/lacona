"""Windows-specific enumeration — services, tasks, auto-runs, ACLs.

All functions gracefully return empty results on non-Windows.
"""

from __future__ import annotations

import logging
import subprocess
import winreg
from pathlib import Path

from lacuna.models import TargetBinary, TriggerMechanism

log = logging.getLogger(__name__)


def is_windows() -> bool:
    import platform
    return platform.system() == "Windows"


def get_known_dlls() -> set[str]:
    """Read KnownDLLs from registry."""
    if not is_windows():
        from lacuna.modules.static_analyzer import KNOWN_DLLS_DEFAULT
        return KNOWN_DLLS_DEFAULT

    known = set()
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs",
        )
        i = 0
        while True:
            try:
                name, value, _ = winreg.EnumValue(key, i)
                known.add(value.lower())
                i += 1
            except OSError:
                break
        winreg.CloseKey(key)
    except OSError:
        log.warning("Could not read KnownDLLs registry key")
    return known


def get_system32_contents() -> set[str]:
    """List all DLLs in System32."""
    if not is_windows():
        return set()
    sys32 = Path("C:/Windows/System32")
    return {f.name.lower() for f in sys32.glob("*.dll")} if sys32.exists() else set()


def get_auto_run_binaries() -> list[TargetBinary]:
    """Enumerate auto-run registry keys."""
    if not is_windows():
        return []

    targets = []
    run_keys = [
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
    ]

    for hive, key_path in run_keys:
        try:
            key = winreg.OpenKey(hive, key_path)
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    # Extract exe path from the value (may have args)
                    exe_path = _extract_exe_path(value)
                    if exe_path and exe_path.exists():
                        targets.append(TargetBinary(
                            path=exe_path,
                            name=exe_path.name,
                            triggers=[TriggerMechanism.AUTO_RUN],
                            runs_as="SYSTEM" if hive == winreg.HKEY_LOCAL_MACHINE else "user",
                        ))
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except OSError:
            continue

    return targets


def get_service_binaries() -> list[TargetBinary]:
    """Enumerate Windows service binaries."""
    if not is_windows():
        return []

    targets = []
    try:
        result = subprocess.run(
            ["wmic", "service", "get", "Name,PathName,StartName,StartMode", "/format:csv"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        for line in result.stdout.strip().split("\n")[2:]:  # Skip headers
            parts = line.strip().split(",")
            if len(parts) >= 4:
                name = parts[1]
                path_name = parts[2]
                start_name = parts[3] if len(parts) > 3 else ""

                exe_path = _extract_exe_path(path_name)
                if exe_path and exe_path.exists() and "windows\\system32\\svchost" not in str(exe_path).lower():
                    runs_as = "SYSTEM" if "LocalSystem" in start_name else "service_account"
                    targets.append(TargetBinary(
                        path=exe_path,
                        name=exe_path.name,
                        triggers=[TriggerMechanism.SERVICE_START],
                        runs_as=runs_as,
                    ))
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        log.warning("Service enumeration failed: %s", e)

    return targets


def get_scheduled_task_binaries() -> list[TargetBinary]:
    """Enumerate scheduled task binaries."""
    if not is_windows():
        return []

    targets = []
    try:
        result = subprocess.run(
            ["schtasks", "/query", "/fo", "csv", "/v"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        import csv
        import io
        reader = csv.DictReader(io.StringIO(result.stdout))
        for row in reader:
            task_run = row.get("Task To Run", "")
            run_as = row.get("Run As User", "")
            exe_path = _extract_exe_path(task_run)
            if exe_path and exe_path.exists() and "system32" not in str(exe_path).lower():
                runs_as = "SYSTEM" if "SYSTEM" in run_as.upper() else "user"
                targets.append(TargetBinary(
                    path=exe_path,
                    name=exe_path.name,
                    triggers=[TriggerMechanism.SCHEDULED_TASK],
                    runs_as=runs_as,
                ))
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        log.warning("Scheduled task enumeration failed: %s", e)

    return targets


def check_dir_writable(directory: Path) -> bool:
    """Check if current user can write to a directory."""
    if not is_windows():
        return False

    try:
        result = subprocess.run(
            ["icacls", str(directory)],
            capture_output=True,
            text=True,
            timeout=5,
        )
        output = result.stdout.lower()
        # Check for write permissions for common user groups
        import os
        username = os.environ.get("USERNAME", "").lower()
        for marker in ["(f)", "(m)", "(w)", "(oi)(ci)(f)", "(oi)(ci)(m)"]:
            if marker in output:
                # Check if it's for our user, authenticated users, or everyone
                for line in output.split("\n"):
                    if marker in line and any(
                        g in line for g in [username, "everyone", "authenticated users", "users"]
                    ):
                        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return False


def get_writable_path_dirs() -> list[Path]:
    """Find PATH directories writable by current user."""
    if not is_windows():
        return []

    import os
    writable = []
    for dir_str in os.environ.get("PATH", "").split(";"):
        dir_path = Path(dir_str)
        if dir_path.exists() and check_dir_writable(dir_path):
            writable.append(dir_path)
    return writable


def _extract_exe_path(raw: str) -> Path | None:
    """Extract exe path from a registry value or command string."""
    if not raw:
        return None

    raw = raw.strip()

    # Handle quoted paths
    if raw.startswith('"'):
        end = raw.find('"', 1)
        if end > 0:
            path_str = raw[1:end]
        else:
            path_str = raw[1:]
    else:
        # Take everything up to first space that's followed by / or -
        parts = raw.split()
        path_str = parts[0] if parts else raw

    path = Path(path_str)
    if path.suffix.lower() in (".exe", ".com", ".scr"):
        return path
    return None
