"""Dynamic monitoring — procmon and ETW-based DLL load capture.

Windows-only module. Captures NAME NOT FOUND events to find
phantom DLL loads that static analysis misses (delay-loaded,
LoadLibrary calls, COM activations, etc.)
"""

from __future__ import annotations

import csv
import logging
import subprocess
import tempfile
import time
from pathlib import Path

from lacuna.models import CandidateStatus, HijackCandidate, HijackType, TargetBinary

log = logging.getLogger(__name__)

PROCMON_FILTERS_TEMPLATE = """
<procmon>
  <FilterRules>
    <FilterRule>
      <Column>Operation</Column>
      <Relation>is</Relation>
      <Value>CreateFile</Value>
      <Action>Include</Action>
    </FilterRule>
    <FilterRule>
      <Column>Result</Column>
      <Relation>contains</Relation>
      <Value>NOT FOUND</Value>
      <Action>Include</Action>
    </FilterRule>
    <FilterRule>
      <Column>Path</Column>
      <Relation>ends with</Relation>
      <Value>.dll</Value>
      <Action>Include</Action>
    </FilterRule>
    <FilterRule>
      <Column>Process Name</Column>
      <Relation>is</Relation>
      <Value>{process_name}</Value>
      <Action>Include</Action>
    </FilterRule>
  </FilterRules>
</procmon>
"""


def generate_procmon_filter(process_name: str, output_path: Path) -> Path:
    """Write a procmon filter config targeting a specific process."""
    content = PROCMON_FILTERS_TEMPLATE.format(process_name=process_name)
    output_path.write_text(content)
    return output_path


def run_procmon_capture(
    target_exe: Path,
    procmon_path: Path | None = None,
    duration_seconds: int = 15,
    target_args: str = "",
) -> Path | None:
    """Launch target under procmon, capture DLL load attempts.

    Returns path to CSV output or None on failure.
    """
    if procmon_path is None:
        procmon_path = Path("C:/Tools/Procmon64.exe")

    if not procmon_path.exists():
        # Try common locations
        for candidate in [
            Path("C:/SysinternalsSuite/Procmon64.exe"),
            Path("C:/tools/Procmon64.exe"),
            Path("C:/Windows/Procmon64.exe"),
        ]:
            if candidate.exists():
                procmon_path = candidate
                break
        else:
            log.error("Procmon not found. Install Sysinternals Suite.")
            return None

    work_dir = Path(tempfile.mkdtemp(prefix="lacuna_"))
    pml_file = work_dir / "capture.pml"
    csv_file = work_dir / "capture.csv"
    filter_file = work_dir / "filter.pmc"

    generate_procmon_filter(target_exe.name, filter_file)

    # Start procmon in background with backing file
    start_cmd = [
        str(procmon_path),
        "/Quiet",
        "/Minimized",
        "/BackingFile", str(pml_file),
        "/LoadConfig", str(filter_file),
    ]

    log.info("Starting procmon capture...")
    proc_mon = subprocess.Popen(start_cmd)
    time.sleep(2)  # Let procmon initialize

    # Launch the target
    log.info("Launching target: %s %s", target_exe, target_args)
    target_cmd = [str(target_exe)]
    if target_args:
        target_cmd.extend(target_args.split())

    try:
        target_proc = subprocess.Popen(target_cmd)
        time.sleep(duration_seconds)
        target_proc.terminate()
    except Exception as e:
        log.error("Failed to launch target: %s", e)

    # Stop procmon and export to CSV
    time.sleep(1)
    subprocess.run(
        [str(procmon_path), "/Terminate"],
        capture_output=True,
        timeout=10,
    )
    time.sleep(2)

    # Convert PML to CSV
    subprocess.run(
        [str(procmon_path), "/OpenLog", str(pml_file), "/SaveAs", str(csv_file)],
        capture_output=True,
        timeout=30,
    )

    if csv_file.exists():
        log.info("Capture saved: %s", csv_file)
        return csv_file
    else:
        log.error("CSV export failed")
        return None


def parse_procmon_csv(csv_path: Path, target_exe_name: str | None = None) -> list[dict]:
    """Parse procmon CSV for NAME NOT FOUND DLL loads.

    Returns list of {process, dll_name, path_attempted, operation}
    """
    results = []

    with open(csv_path, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if "NAME NOT FOUND" not in row.get("Result", ""):
                continue
            path = row.get("Path", "")
            if not path.lower().endswith(".dll"):
                continue
            if target_exe_name and row.get("Process Name", "").lower() != target_exe_name.lower():
                continue

            dll_name = Path(path).name
            results.append({
                "process": row.get("Process Name", ""),
                "pid": row.get("PID", ""),
                "dll_name": dll_name,
                "path_attempted": path,
                "operation": row.get("Operation", ""),
            })

    # Deduplicate by (process, dll_name)
    seen = set()
    deduped = []
    for r in results:
        key = (r["process"], r["dll_name"].lower())
        if key not in seen:
            seen.add(key)
            deduped.append(r)

    return deduped


def phantom_dlls_to_candidates(
    phantoms: list[dict],
    target: TargetBinary,
) -> list[HijackCandidate]:
    """Convert procmon phantom DLL findings to HijackCandidates."""
    candidates = []
    for p in phantoms:
        candidate = HijackCandidate(
            target=target,
            dll_name=p["dll_name"],
            hijack_type=HijackType.PHANTOM,
            status=CandidateStatus.DYNAMIC_CONFIRMED,
            plant_path=Path(p["path_attempted"]).parent,
            notes=[f"Attempted load path: {p['path_attempted']}"],
        )
        candidates.append(candidate)
    return candidates


def etw_dll_monitor(target_exe: Path, duration_seconds: int = 15) -> list[dict]:
    """Use ETW via PowerShell to capture DLL load events.

    Fallback when procmon isn't available. Less comprehensive but
    doesn't require Sysinternals.
    """
    ps_script = f"""
    $events = @()
    $job = Start-Job -ScriptBlock {{
        $proc = Start-Process -FilePath "{target_exe}" -PassThru
        Start-Sleep -Seconds {duration_seconds}
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    }}
    # Use Get-WinEvent with Microsoft-Windows-Kernel-Process provider
    Start-Sleep -Seconds {duration_seconds + 3}
    $events = Get-WinEvent -FilterHashtable @{{
        LogName='Microsoft-Windows-Kernel-Process/Analytic'
        Id=5  # ImageLoad
    }} -MaxEvents 1000 -ErrorAction SilentlyContinue |
    Where-Object {{ $_.Message -like "*{target_exe.name}*" }}
    $events | Select-Object TimeCreated, Message | ConvertTo-Json
    """

    try:
        result = subprocess.run(
            ["powershell", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
            capture_output=True,
            text=True,
            timeout=duration_seconds + 15,
        )
        if result.stdout.strip():
            import json
            return json.loads(result.stdout)
    except Exception as e:
        log.warning("ETW monitor failed: %s", e)

    return []
