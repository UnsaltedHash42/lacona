"""Remote validation — deploy canary, trigger app, check breadcrumb, restore."""

from __future__ import annotations

import base64
import hashlib
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path, PureWindowsPath

log = logging.getLogger(__name__)


@dataclass
class ValidationTarget:
    host: str
    username: str
    password: str | None = None
    key_path: str | None = None
    transport: str = "winrm"  # winrm | ssh
    port: int | None = None


@dataclass
class ValidationResult:
    candidate_dll: str
    host_exe: str
    success: bool
    breadcrumb_content: str | None = None
    process_survived: bool = False
    error: str | None = None
    duration_seconds: float = 0.0
    notes: list[str] = field(default_factory=list)
    restore_verified: bool = True


class RemoteValidator:
    """Validates hijack candidates against a remote Windows host."""

    def __init__(self, target: ValidationTarget, work_dir: str = r"C:\Temp\lacuna"):
        self.target = target
        self.work_dir = work_dir
        self.session = None

    def connect(self):
        """Establish remote session."""
        if self.target.transport == "winrm":
            import winrm
            port = self.target.port or 5985
            self.session = winrm.Session(
                f"http://{self.target.host}:{port}/wsman",
                auth=(self.target.username, self.target.password),
                transport="ntlm",
            )
            # Test connectivity
            result = self.session.run_ps("$env:COMPUTERNAME")
            hostname = result.std_out.decode().strip()
            log.info("Connected to %s via WinRM", hostname)

        elif self.target.transport == "ssh":
            import paramiko
            self.session = paramiko.SSHClient()
            self.session.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.session.connect(
                self.target.host,
                port=self.target.port or 22,
                username=self.target.username,
                password=self.target.password,
                key_filename=self.target.key_path,
            )
            log.info("Connected to %s via SSH", self.target.host)

    def disconnect(self):
        """Close the remote session."""
        if self.target.transport == "ssh" and self.session:
            self.session.close()
        self.session = None

    def validate_candidate(
        self,
        candidate: dict,
        canary_dll_path: Path,
        timeout: int = 30,
    ) -> ValidationResult:
        """Full validation cycle for one candidate.

        Steps:
        1. Upload compiled canary DLL to remote work dir
        2. Backup original DLL (rename to .bak)
        3. Place canary as the target DLL name
        4. Launch the host application
        5. Wait for breadcrumb (poll remote filesystem)
        6. Record process survival (is it still running?)
        7. Kill the app
        8. Restore original DLL from .bak
        9. Return result
        """
        dll_name = candidate["dll_name"]
        host_exe = candidate.get("host_exe", candidate.get("host_path", "unknown.exe"))
        dll_path = candidate.get("dll_path", "")
        host_path = candidate.get("host_path", "")

        start_time = time.time()
        result = ValidationResult(
            candidate_dll=dll_name,
            host_exe=Path(host_exe).name if host_exe else dll_name,
            success=False,
        )

        try:
            # Ensure work directory exists
            self._run_remote(
                f"New-Item -ItemType Directory -Force -Path '{self.work_dir}\\breadcrumbs'"
            )

            # Upload canary DLL
            remote_canary = f"{self.work_dir}\\{dll_name}"
            self._upload_file(str(canary_dll_path), remote_canary)

            # Hash original for later verification
            original_hash = None
            if dll_path:
                hash_cmd = (
                    f"if (Test-Path '{dll_path}') {{"
                    f"  (Get-FileHash '{dll_path}' -Algorithm SHA256).Hash"
                    f"}}"
                )
                _, stdout, _ = self._run_remote(hash_cmd)
                original_hash = stdout.strip() if stdout.strip() else None

            # Backup original (if it exists)
            if dll_path:
                self._run_remote(
                    f"if (Test-Path '{dll_path}') {{"
                    f"  Copy-Item '{dll_path}' '{dll_path}.lacuna_bak' -Force"
                    f"}}"
                )

            try:
                # Deploy canary
                if dll_path:
                    self._run_remote(f"Copy-Item '{remote_canary}' '{dll_path}' -Force")
                else:
                    target_dir = str(PureWindowsPath(host_path).parent) if host_path else self.work_dir
                    self._run_remote(
                        f"Copy-Item '{remote_canary}' '{target_dir}\\{dll_name}' -Force"
                    )

                # Launch host application
                launch_cmd = (
                    f"$proc = Start-Process '{host_path}' -PassThru -ErrorAction Stop; "
                    f"$proc.Id"
                )
                _, stdout, stderr = self._run_remote(launch_cmd)
                proc_id = stdout.strip()

                # Wait for breadcrumb
                breadcrumb_path = f"{self.work_dir}\\breadcrumbs\\lacuna_{dll_name}.breadcrumb"
                deadline = time.time() + timeout
                hit = False

                while time.time() < deadline:
                    check_cmd = f"Test-Path '{breadcrumb_path}'"
                    _, stdout, _ = self._run_remote(check_cmd)
                    if "True" in stdout:
                        hit = True
                        break
                    time.sleep(2)

                if hit:
                    _, content, _ = self._run_remote(f"Get-Content '{breadcrumb_path}'")
                    result.breadcrumb_content = content.strip()
                    result.success = True

                # Check process survival
                if proc_id:
                    _, stdout, _ = self._run_remote(
                        f"Get-Process -Id {proc_id} -ErrorAction SilentlyContinue | "
                        f"Select-Object -ExpandProperty Id"
                    )
                    result.process_survived = bool(stdout.strip())

                # Kill the process
                if proc_id:
                    self._run_remote(
                        f"Stop-Process -Id {proc_id} -Force -ErrorAction SilentlyContinue"
                    )

            finally:
                # Restore original
                if dll_path:
                    self._run_remote(
                        f"if (Test-Path '{dll_path}.lacuna_bak') {{"
                        f"  Copy-Item '{dll_path}.lacuna_bak' '{dll_path}' -Force; "
                        f"  Remove-Item '{dll_path}.lacuna_bak' -Force"
                        f"}}"
                    )

                # Verify restoration
                if original_hash and dll_path:
                    _, stdout, _ = self._run_remote(
                        f"(Get-FileHash '{dll_path}' -Algorithm SHA256).Hash"
                    )
                    restored_hash = stdout.strip()
                    if restored_hash != original_hash:
                        log.error(
                            "RESTORE VERIFICATION FAILED for %s — hash mismatch", dll_path
                        )
                        result.restore_verified = False
                        result.notes.append(
                            f"Restore hash mismatch: expected {original_hash}, "
                            f"got {restored_hash}"
                        )

                # Clean up breadcrumb
                self._run_remote(
                    f"Remove-Item '{breadcrumb_path}' -Force -ErrorAction SilentlyContinue"
                )

        except Exception as e:
            result.error = str(e)
            log.error("Validation failed for %s: %s", dll_name, e)

        result.duration_seconds = time.time() - start_time
        return result

    def validate_batch(
        self,
        candidates: list[dict],
        canary_dir: Path,
        max_parallel: int = 1,
    ) -> list[ValidationResult]:
        """Validate a list of candidates sequentially."""
        results = []
        for candidate in candidates:
            dll_name = candidate["dll_name"]
            canary_path = canary_dir / dll_name
            if not canary_path.exists():
                results.append(ValidationResult(
                    candidate_dll=dll_name,
                    host_exe=candidate.get("host_exe", "unknown"),
                    success=False,
                    error=f"Canary DLL not found: {canary_path}",
                ))
                continue
            result = self.validate_candidate(candidate, canary_path)
            results.append(result)
            log.info(
                "%s via %s: %s (%.1fs)",
                dll_name,
                result.host_exe,
                "HIT" if result.success else "MISS",
                result.duration_seconds,
            )
        return results

    def _run_remote(self, command: str) -> tuple[int, str, str]:
        """Execute command on remote host. Returns (exit_code, stdout, stderr)."""
        if self.target.transport == "winrm":
            result = self.session.run_ps(command)
            return (
                result.status_code,
                result.std_out.decode("utf-8", errors="replace"),
                result.std_err.decode("utf-8", errors="replace"),
            )
        elif self.target.transport == "ssh":
            _, stdout, stderr = self.session.exec_command(command)
            exit_code = stdout.channel.recv_exit_status()
            return (
                exit_code,
                stdout.read().decode("utf-8", errors="replace"),
                stderr.read().decode("utf-8", errors="replace"),
            )
        raise ValueError(f"Unknown transport: {self.target.transport}")

    def _upload_file(self, local_path: str, remote_path: str):
        """Upload file to remote host."""
        if self.target.transport == "winrm":
            with open(local_path, "rb") as f:
                content = base64.b64encode(f.read()).decode()
            # Chunk large files (WinRM has command size limits)
            chunk_size = 60000  # ~60KB chunks (base64)
            if len(content) <= chunk_size:
                self._run_remote(
                    f"[IO.File]::WriteAllBytes('{remote_path}', "
                    f"[Convert]::FromBase64String('{content}'))"
                )
            else:
                # Write in chunks
                self._run_remote(
                    f"$null = New-Item -ItemType File -Force -Path '{remote_path}'"
                )
                for i in range(0, len(content), chunk_size):
                    chunk = content[i:i + chunk_size]
                    self._run_remote(
                        f"$bytes = [Convert]::FromBase64String('{chunk}'); "
                        f"$stream = [IO.File]::Open('{remote_path}', "
                        f"[IO.FileMode]::Append); "
                        f"$stream.Write($bytes, 0, $bytes.Length); "
                        f"$stream.Close()"
                    )
        elif self.target.transport == "ssh":
            sftp = self.session.open_sftp()
            sftp.put(local_path, remote_path)
            sftp.close()
        else:
            raise ValueError(f"Unknown transport: {self.target.transport}")

    def _download_file(self, remote_path: str, local_path: str):
        """Download file from remote host."""
        if self.target.transport == "winrm":
            _, stdout, _ = self._run_remote(
                f"[Convert]::ToBase64String([IO.File]::ReadAllBytes('{remote_path}'))"
            )
            data = base64.b64decode(stdout.strip())
            with open(local_path, "wb") as f:
                f.write(data)
        elif self.target.transport == "ssh":
            sftp = self.session.open_sftp()
            sftp.get(remote_path, local_path)
            sftp.close()
        else:
            raise ValueError(f"Unknown transport: {self.target.transport}")
