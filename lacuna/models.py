"""Core data models for Lacuna."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class HijackType(Enum):
    SEARCH_ORDER = "search_order"
    PHANTOM = "phantom"  # DLL that doesn't exist anywhere
    PATH_DIR = "path_dir"  # writable PATH directory
    SIDE_LOAD = "side_load"  # app-dir placement


class TriggerMechanism(Enum):
    AUTO_RUN = "auto_run"
    SERVICE_START = "service_start"
    SCHEDULED_TASK = "scheduled_task"
    USER_LAUNCH = "user_launch"
    COM_ACTIVATION = "com_activation"
    UNKNOWN = "unknown"


class CandidateStatus(Enum):
    DISCOVERED = "discovered"
    STATIC_CONFIRMED = "static_confirmed"
    DYNAMIC_CONFIRMED = "dynamic_confirmed"
    CANARY_SUCCESS = "canary_success"
    PROXY_GENERATED = "proxy_generated"
    VALIDATED = "validated"
    REJECTED = "rejected"


@dataclass
class TargetBinary:
    path: Path
    name: str
    signer: str | None = None
    is_signed: bool = False
    arch: str = "x64"
    imports: list[str] = field(default_factory=list)
    triggers: list[TriggerMechanism] = field(default_factory=list)
    runs_as: str = "user"  # user | SYSTEM | service_account


@dataclass
class HijackCandidate:
    target: TargetBinary
    dll_name: str
    hijack_type: HijackType
    status: CandidateStatus = CandidateStatus.DISCOVERED
    score: float = 0.0
    plant_path: Path | None = None
    is_known_dll: bool = False
    is_on_hijacklibs: bool = False
    export_count: int = 0
    notes: list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    candidates: list[HijackCandidate] = field(default_factory=list)
    targets_scanned: int = 0
    known_dlls: set[str] = field(default_factory=set)
    errors: list[str] = field(default_factory=list)


@dataclass
class AcquisitionTarget:
    """A software package the agent suggests installing for scanning."""

    name: str
    vendor: str
    category: str  # rmm, backup, vpn, conferencing, dev_tool, print, av, etc.
    rationale: str
    install_method: str | None = None  # winget id, choco id, or URL
    runs_as_system: bool = False
    has_updater: bool = False
    already_known: bool = False  # on hijacklibs.net
