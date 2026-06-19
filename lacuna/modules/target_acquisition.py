"""Target acquisition — suggest and fetch software to scan.

The agent uses this module to:
1. Suggest software the operator should install based on category/criteria
2. Query winget/choco for installable candidates
3. Filter against hijacklibs.net known targets
4. Prioritize by SYSTEM-context, auto-start, updater presence
"""

from __future__ import annotations

import json
import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path

from lacuna.models import AcquisitionTarget

log = logging.getLogger(__name__)

# Categories of software likely to have DLL hijack surface:
# - Runs as SYSTEM or elevated
# - Has background services / updaters
# - Ships many DLLs in its own directory
# - Popular enough to be "trusted" by defenders
SOFTWARE_CATALOG: list[AcquisitionTarget] = [
    # RMM / IT management
    AcquisitionTarget(
        name="ConnectWise ScreenConnect",
        vendor="ConnectWise",
        category="rmm",
        rationale="RMM agent runs as SYSTEM, has updater service, loads DLLs from install dir",
        install_method="manual:https://screenconnect.connectwise.com/download",
        runs_as_system=True,
        has_updater=True,
    ),
    AcquisitionTarget(
        name="PDQ Deploy",
        vendor="PDQ",
        category="rmm",
        rationale="Deployment tool runs as SYSTEM service, complex DLL dependencies",
        install_method="manual:https://www.pdq.com/downloads/",
        runs_as_system=True,
        has_updater=True,
    ),
    AcquisitionTarget(
        name="NinjaRMM Agent",
        vendor="NinjaOne",
        category="rmm",
        rationale="Widely deployed RMM, SYSTEM service, auto-updates",
        install_method="manual:org-specific",
        runs_as_system=True,
        has_updater=True,
    ),
    # Backup
    AcquisitionTarget(
        name="Veeam Agent",
        vendor="Veeam",
        category="backup",
        rationale="Backup agent runs as SYSTEM, massive import table, many proprietary DLLs",
        install_method="manual:https://www.veeam.com/agent-for-windows-community-edition.html",
        runs_as_system=True,
        has_updater=True,
    ),
    AcquisitionTarget(
        name="Acronis Cyber Protect",
        vendor="Acronis",
        category="backup",
        rationale="Heavy backup suite, multiple SYSTEM services, complex DLL deps",
        install_method="manual:https://www.acronis.com/en-us/products/cyber-protect-home-office/",
        runs_as_system=True,
        has_updater=True,
    ),
    # VPN / Network
    AcquisitionTarget(
        name="Cisco AnyConnect / Secure Client",
        vendor="Cisco",
        category="vpn",
        rationale="Enterprise VPN, SYSTEM service, loads modules dynamically",
        install_method="manual:org-specific",
        runs_as_system=True,
        has_updater=True,
    ),
    AcquisitionTarget(
        name="GlobalProtect",
        vendor="Palo Alto",
        category="vpn",
        rationale="Enterprise VPN client, SYSTEM service + user tray app",
        install_method="manual:org-specific",
        runs_as_system=True,
        has_updater=True,
    ),
    AcquisitionTarget(
        name="WireGuard",
        vendor="WireGuard",
        category="vpn",
        rationale="Lightweight but SYSTEM tunnel service; small attack surface worth checking",
        install_method="winget:WireGuard.WireGuard",
        runs_as_system=True,
        has_updater=False,
    ),
    # Conferencing / Collaboration
    AcquisitionTarget(
        name="Zoom Workplace",
        vendor="Zoom",
        category="conferencing",
        rationale="User-space app with SYSTEM updater service, massive DLL footprint",
        install_method="winget:Zoom.Zoom",
        runs_as_system=False,
        has_updater=True,
    ),
    AcquisitionTarget(
        name="Webex",
        vendor="Cisco",
        category="conferencing",
        rationale="Enterprise conferencing, background services, updater",
        install_method="winget:Cisco.Webex",
        runs_as_system=False,
        has_updater=True,
    ),
    # Dev tools
    AcquisitionTarget(
        name="JetBrains Toolbox",
        vendor="JetBrains",
        category="dev_tool",
        rationale="Manages IDE installs, background service, loads plugins dynamically",
        install_method="winget:JetBrains.Toolbox",
        runs_as_system=False,
        has_updater=True,
    ),
    AcquisitionTarget(
        name="Git for Windows",
        vendor="Git",
        category="dev_tool",
        rationale="Ships many DLLs in bin/ — common PATH pollution target",
        install_method="winget:Git.Git",
        runs_as_system=False,
        has_updater=False,
    ),
    AcquisitionTarget(
        name="Python (CPython)",
        vendor="PSF",
        category="dev_tool",
        rationale="Installs to user-writable path by default, adds to PATH, many DLLs",
        install_method="winget:Python.Python.3.12",
        runs_as_system=False,
        has_updater=False,
    ),
    # Print / Peripheral management
    AcquisitionTarget(
        name="PaperCut MF/NG",
        vendor="PaperCut",
        category="print",
        rationale="Print management, SYSTEM service, Java + native DLL mix",
        install_method="manual:https://www.papercut.com/products/ng/",
        runs_as_system=True,
        has_updater=True,
    ),
    # AV / Security (ironic targets)
    AcquisitionTarget(
        name="Symantec Endpoint Protection",
        vendor="Broadcom",
        category="av",
        rationale="AV with SYSTEM services, driver + userland DLLs, historically hijackable",
        install_method="manual:org-specific",
        runs_as_system=True,
        has_updater=True,
    ),
    # Database / Middleware
    AcquisitionTarget(
        name="SQL Server Management Studio",
        vendor="Microsoft",
        category="dev_tool",
        rationale="Microsoft-signed, massive import table, user-space with many DLL loads",
        install_method="winget:Microsoft.SQLServerManagementStudio",
        runs_as_system=False,
        has_updater=False,
    ),
    AcquisitionTarget(
        name="Azure Data Studio",
        vendor="Microsoft",
        category="dev_tool",
        rationale="Electron app, Microsoft-signed, ships hundreds of DLLs in app dir",
        install_method="winget:Microsoft.AzureDataStudio",
        runs_as_system=False,
        has_updater=True,
    ),
    # Monitoring / Observability agents
    AcquisitionTarget(
        name="Datadog Agent",
        vendor="Datadog",
        category="monitoring",
        rationale="SYSTEM service, Go binary but loads native DLLs for integrations",
        install_method="manual:https://app.datadoghq.com/account/settings#agent/windows",
        runs_as_system=True,
        has_updater=True,
    ),
    AcquisitionTarget(
        name="Splunk Universal Forwarder",
        vendor="Splunk",
        category="monitoring",
        rationale="SYSTEM service, loads scripting DLLs, common in enterprise",
        install_method="manual:https://www.splunk.com/en_us/download/universal-forwarder.html",
        runs_as_system=True,
        has_updater=True,
    ),
]


def query_winget_installed() -> list[dict]:
    """Query winget for installed packages (Windows only)."""
    try:
        result = subprocess.run(
            ["winget", "list", "--accept-source-agreements", "--disable-interactivity"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        # Parse winget's table output — messy but functional
        lines = result.stdout.strip().split("\n")
        packages = []
        header_found = False
        for line in lines:
            if "----" in line:
                header_found = True
                continue
            if header_found and line.strip():
                parts = line.split()
                if len(parts) >= 2:
                    packages.append({"name": " ".join(parts[:-2]), "id": parts[-2]})
        return packages
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []


def query_winget_search(query: str) -> list[dict]:
    """Search winget for available packages."""
    try:
        result = subprocess.run(
            ["winget", "search", query, "--accept-source-agreements", "--disable-interactivity"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        lines = result.stdout.strip().split("\n")
        packages = []
        header_found = False
        for line in lines:
            if "----" in line:
                header_found = True
                continue
            if header_found and line.strip():
                parts = line.split()
                if len(parts) >= 2:
                    packages.append({"name": " ".join(parts[:-2]), "id": parts[-2]})
        return packages
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []


def install_via_winget(package_id: str) -> bool:
    """Install a package via winget. Returns True on success."""
    try:
        result = subprocess.run(
            [
                "winget", "install", package_id,
                "--accept-package-agreements",
                "--accept-source-agreements",
                "--disable-interactivity",
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def get_suggestions(
    installed_names: list[str] | None = None,
    burned_targets: set[str] | None = None,
    category_filter: str | None = None,
    system_only: bool = False,
) -> list[AcquisitionTarget]:
    """Return acquisition targets filtered by criteria.

    Args:
        installed_names: Names already on the box (skip these)
        burned_targets: Names on hijacklibs.net (flag but don't skip)
        category_filter: Only return targets in this category
        system_only: Only return targets that run as SYSTEM
    """
    if installed_names is None:
        installed_names = []
    if burned_targets is None:
        burned_targets = set()

    installed_lower = {n.lower() for n in installed_names}
    suggestions = []

    for target in SOFTWARE_CATALOG:
        if target.name.lower() in installed_lower:
            continue
        if category_filter and target.category != category_filter:
            continue
        if system_only and not target.runs_as_system:
            continue
        if target.name.lower() in burned_targets:
            target.already_known = True
        suggestions.append(target)

    # Sort: SYSTEM first, then has_updater, then not-already-known
    suggestions.sort(
        key=lambda t: (not t.runs_as_system, not t.has_updater, t.already_known)
    )
    return suggestions


def format_suggestions(targets: list[AcquisitionTarget]) -> str:
    """Format suggestions for display to operator."""
    lines = []
    for i, t in enumerate(targets, 1):
        flags = []
        if t.runs_as_system:
            flags.append("SYSTEM")
        if t.has_updater:
            flags.append("updater")
        if t.already_known:
            flags.append("BURNED")
        flag_str = f" [{', '.join(flags)}]" if flags else ""

        lines.append(f"{i:2}. {t.name} ({t.vendor}) — {t.category}{flag_str}")
        lines.append(f"    {t.rationale}")
        if t.install_method:
            lines.append(f"    Install: {t.install_method}")
        lines.append("")

    return "\n".join(lines)
