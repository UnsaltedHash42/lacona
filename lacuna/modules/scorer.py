"""Operability scoring — ranks hijack candidates by exploitation value."""

from __future__ import annotations

from lacuna.models import HijackCandidate, HijackType, TriggerMechanism

WEIGHTS = {
    "user_writable_path": 30,
    "auto_start": 25,
    "runs_as_system": 20,
    "is_novel": 15,
    "phantom_dll": 15,
    "low_exports": 10,
    "delay_load": 10,
    "trusted_signer": 10,
    "universal_proxy": 10,
    "moderate_exports": 5,
    "has_updater": 5,
    "dll_unsigned": 5,
}

USER_WRITABLE_MARKERS = [
    "appdata\\local", "appdata\\roaming", "%localappdata%",
    "\\users\\", "\\temp\\", "\\tmp\\",
    "appdata/local", "appdata/roaming",
    "/users/", "/temp/", "/tmp/",
]

UPDATER_MARKERS = [
    "update.exe", "squirrel.exe", "updater.exe",
    "update-helper", "update-notifier",
]


def score_candidate(
    candidate: HijackCandidate,
    all_candidates: list[HijackCandidate] | None = None,
) -> tuple[int, dict[str, int]]:
    """Compute operability score for a single candidate.

    Returns (total_score, breakdown_dict).
    """
    breakdown: dict[str, int] = {}

    # Path writability
    path_str = str(candidate.target.path).lower()
    if any(marker in path_str for marker in USER_WRITABLE_MARKERS):
        breakdown["user_writable_path"] = WEIGHTS["user_writable_path"]

    # Trigger mechanism — auto-start
    auto_triggers = {TriggerMechanism.AUTO_RUN, TriggerMechanism.SERVICE_START,
                     TriggerMechanism.SCHEDULED_TASK}
    if any(t in auto_triggers for t in candidate.target.triggers):
        breakdown["auto_start"] = WEIGHTS["auto_start"]

    # Execution context
    if candidate.target.runs_as == "SYSTEM":
        breakdown["runs_as_system"] = WEIGHTS["runs_as_system"]

    # Novelty
    if not candidate.is_on_hijacklibs:
        breakdown["is_novel"] = WEIGHTS["is_novel"]

    # Phantom (no original to rename)
    if candidate.hijack_type == HijackType.PHANTOM:
        breakdown["phantom_dll"] = WEIGHTS["phantom_dll"]

    # Export count
    if 0 < candidate.export_count <= 5:
        breakdown["low_exports"] = WEIGHTS["low_exports"]
    elif 5 < candidate.export_count <= 20:
        breakdown["moderate_exports"] = WEIGHTS["moderate_exports"]

    # Delay load
    if candidate.hijack_type == HijackType.DELAY_LOAD:
        breakdown["delay_load"] = WEIGHTS["delay_load"]

    # Trusted signer on the HOST (LOLbin value)
    if candidate.target.is_signed:
        breakdown["trusted_signer"] = WEIGHTS["trusted_signer"]

    # Universal proxy (same DLL name across multiple targets)
    if all_candidates:
        same_dll_count = sum(
            1 for c in all_candidates
            if c.dll_name == candidate.dll_name and c.target.name != candidate.target.name
        )
        if same_dll_count >= 2:
            breakdown["universal_proxy"] = WEIGHTS["universal_proxy"]

    # Auto-updater heuristic (check sibling filenames in the target dir)
    try:
        target_dir = candidate.target.path.parent
        if target_dir.exists():
            siblings = {f.name.lower() for f in target_dir.iterdir() if f.is_file()}
            if any(marker in siblings for marker in UPDATER_MARKERS):
                breakdown["has_updater"] = WEIGHTS["has_updater"]
    except (OSError, PermissionError):
        pass

    total = sum(breakdown.values())
    return total, breakdown


def score_candidates(
    candidates: list[HijackCandidate],
) -> list[HijackCandidate]:
    """Score all candidates and set score/score_breakdown fields. Returns sorted list."""
    for c in candidates:
        total, breakdown = score_candidate(c, all_candidates=candidates)
        c.score = total
        c.score_breakdown = breakdown

    return sorted(candidates, key=lambda x: x.score, reverse=True)
