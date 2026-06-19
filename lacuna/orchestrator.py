"""Lacuna orchestrator — connects agent decisions to module execution.

The main loop:
1. Agent decides what to do
2. Orchestrator executes via appropriate module
3. Results fed back to agent as observations
4. Repeat until agent reports or operator interrupts
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from lacuna.agent import ActionType, AgentAction, LacunaAgent
from lacuna.models import CandidateStatus, HijackCandidate
from lacuna.modules.hijacklibs import novelty_check
from lacuna.modules.static_analyzer import analyze_binary, scan_directory

log = logging.getLogger(__name__)
console = Console()


class Orchestrator:
    def __init__(self, agent: LacunaAgent, work_dir: Path | None = None):
        self.agent = agent
        self.work_dir = work_dir or Path.cwd() / "lacuna_output"
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.all_candidates: list[HijackCandidate] = []
        self.confirmed: list[HijackCandidate] = []
        self.max_iterations = 50
        self.interactive = True

    def run(self, initial_context: str | None = None):
        """Main agent loop."""
        if initial_context:
            self.agent.set_operator_context(initial_context)

        console.print(Panel(
            "[bold green]Lacuna[/] — Agentic DLL Hijack Discovery\n"
            f"Work dir: {self.work_dir}",
            title="Session Start",
        ))

        actions = self.agent.get_initial_actions()
        iteration = 0

        while iteration < self.max_iterations:
            iteration += 1
            console.print(f"\n[dim]─── Iteration {iteration} ───[/dim]")

            for action in actions:
                self._display_action(action)
                result = self._execute_action(action)
                self.agent.update_state(action, result)

                if action.action_type == ActionType.REPORT:
                    self._display_report(result)
                    return result

                if action.action_type == ActionType.ASK_OPERATOR:
                    operator_response = self._ask_operator(action.params)
                    result["operator_response"] = operator_response

                # Feed result back to agent
                observation = {
                    "type": "action_result",
                    "action_executed": action.action_type.value,
                    "params": action.params,
                    "result": result,
                }
                actions = self.agent.decide(observation)
                break  # Process one action at a time for observability

        console.print("[yellow]Max iterations reached. Generating final report.[/yellow]")
        return self._generate_final_report()

    def _execute_action(self, action: AgentAction) -> dict:
        """Route action to appropriate module."""
        try:
            match action.action_type:
                case ActionType.SCAN_DIRECTORY:
                    return self._do_scan_directory(action.params)
                case ActionType.SCAN_BINARY:
                    return self._do_scan_binary(action.params)
                case ActionType.RUN_DYNAMIC:
                    return self._do_dynamic(action.params)
                case ActionType.PROMOTE:
                    return self._do_promote(action.params)
                case ActionType.REJECT:
                    return self._do_reject(action.params)
                case ActionType.DEPLOY_CANARY:
                    return self._do_canary(action.params)
                case ActionType.GENERATE_PROXY:
                    return self._do_proxy(action.params)
                case ActionType.SUGGEST_ACQUISITION:
                    return self._do_suggest(action.params)
                case ActionType.ASK_OPERATOR:
                    return {"awaiting_response": True}
                case ActionType.REPORT:
                    return action.params
                case _:
                    return {"error": f"Unknown action: {action.action_type}"}
        except Exception as e:
            log.error("Action failed: %s — %s", action.action_type, e)
            return {"error": str(e)}

    def _do_scan_directory(self, params: dict) -> dict:
        path = Path(params.get("path", ""))
        if not path.exists():
            return {"error": f"Path does not exist: {path}"}

        candidates = scan_directory(
            path,
            recursive=params.get("recursive", True),
        )

        # Novelty-check each candidate
        novel = []
        burned = []
        for c in candidates:
            check = novelty_check(c.dll_name, c.target.name)
            if check["is_novel"]:
                c.notes.append(f"Novelty: {check['reason']}")
                novel.append(c)
            else:
                c.notes.append(f"BURNED: {check['reason']}")
                burned.append(c)

        self.all_candidates.extend(novel)

        return {
            "path": str(path),
            "total_candidates": len(candidates),
            "novel_candidates": len(novel),
            "burned_candidates": len(burned),
            "novel": [
                {"dll": c.dll_name, "exe": c.target.name, "type": c.hijack_type.value}
                for c in novel[:20]  # Top 20 for agent context
            ],
        }

    def _do_scan_binary(self, params: dict) -> dict:
        path = Path(params.get("path", ""))
        if not path.exists():
            return {"error": f"Binary does not exist: {path}"}

        candidates = analyze_binary(path)
        novel = []
        for c in candidates:
            check = novelty_check(c.dll_name, c.target.name)
            if check["is_novel"]:
                c.notes.append(f"Novelty: {check['reason']}")
                novel.append(c)

        self.all_candidates.extend(novel)
        return {
            "binary": path.name,
            "imports": len(candidates),
            "novel": [
                {"dll": c.dll_name, "type": c.hijack_type.value}
                for c in novel
            ],
        }

    def _do_dynamic(self, params: dict) -> dict:
        from lacuna.modules.dynamic_monitor import (
            parse_procmon_csv,
            run_procmon_capture,
        )

        target_exe = Path(params.get("target_exe", ""))
        duration = params.get("duration_seconds", 15)

        csv_path = run_procmon_capture(target_exe, duration_seconds=duration)
        if csv_path is None:
            return {"error": "Procmon capture failed"}

        phantoms = parse_procmon_csv(csv_path, target_exe.name)
        return {
            "target": target_exe.name,
            "phantom_dlls": phantoms,
            "count": len(phantoms),
        }

    def _do_promote(self, params: dict) -> dict:
        console.print(f"  [green]PROMOTED:[/] {params.get('dll_name')} via {params.get('target_exe')}")
        console.print(f"  [dim]{params.get('reason', '')}[/dim]")
        return {"promoted": True}

    def _do_reject(self, params: dict) -> dict:
        console.print(f"  [red]REJECTED:[/] {params.get('dll_name')} — {params.get('reason', '')}")
        return {"rejected": True}

    def _do_canary(self, params: dict) -> dict:
        from lacuna.modules.canary import (
            check_breadcrumb,
            cleanup_canary,
            compile_canary,
            deploy_canary,
            generate_canary_source,
        )

        dll_name = params.get("dll_name", "")
        target_exe = params.get("target_exe", "")
        plant_path = Path(params.get("plant_path", ""))

        breadcrumb_dir = self.work_dir / "breadcrumbs"
        breadcrumb_dir.mkdir(exist_ok=True)

        source = generate_canary_source(dll_name, target_exe, breadcrumb_dir)
        canary_path = self.work_dir / "canaries" / dll_name
        canary_path.parent.mkdir(parents=True, exist_ok=True)

        if not compile_canary(source, canary_path):
            return {"success": False, "error": "Compilation failed"}

        deploy_canary(canary_path, plant_path, dll_name)

        # The operator needs to trigger the target app
        console.print(f"  [yellow]Canary deployed:[/] {plant_path / dll_name}")
        console.print(f"  [yellow]Trigger:[/] Launch {target_exe}")

        if self.interactive:
            input("  Press Enter after triggering the target app...")

        result = check_breadcrumb(breadcrumb_dir, dll_name, timeout_seconds=10)
        cleanup_canary(plant_path, dll_name, breadcrumb_dir)

        if result:
            console.print(f"  [bold green]CANARY HIT![/] {dll_name} loaded by {target_exe}")
            return {"success": True, "breadcrumb": result}
        else:
            console.print(f"  [red]No breadcrumb — canary was not loaded[/]")
            return {"success": False, "error": "DLL was not loaded"}

    def _do_proxy(self, params: dict) -> dict:
        from lacuna.modules.proxy_generator import write_proxy_project

        dll_path = Path(params.get("dll_path", ""))
        if not dll_path.exists():
            return {"error": f"DLL not found: {dll_path}"}

        output_dir = self.work_dir / "proxies" / dll_path.stem
        files = write_proxy_project(dll_path, output_dir)

        console.print(f"  [green]Proxy project written:[/] {output_dir}")
        return {
            "output_dir": str(output_dir),
            "files": {k: str(v) for k, v in files.items()},
        }

    def _do_suggest(self, params: dict) -> dict:
        from lacuna.modules.target_acquisition import format_suggestions

        targets = params.get("targets", [])
        formatted = []
        for t in targets:
            formatted.append(
                f"• {t.get('name', '?')} ({t.get('category', '?')}) — {t.get('rationale', '')}"
            )

        console.print(Panel(
            "\n".join(formatted),
            title="[yellow]Agent suggests acquiring these targets[/]",
        ))
        return {"suggested": len(targets)}

    def _ask_operator(self, params: dict) -> str:
        """Interactive prompt for operator input."""
        console.print(Panel(
            params.get("question", "Input needed"),
            title="[yellow]Agent Question[/]",
        ))
        if params.get("context"):
            console.print(f"  [dim]Context: {params['context']}[/dim]")

        if self.interactive:
            return input("  > ")
        return ""

    def _display_action(self, action: AgentAction):
        """Display an action for operator visibility."""
        icon = {
            ActionType.SCAN_DIRECTORY: "🔍",
            ActionType.SCAN_BINARY: "🔬",
            ActionType.RUN_DYNAMIC: "⚡",
            ActionType.PROMOTE: "⬆️",
            ActionType.REJECT: "❌",
            ActionType.DEPLOY_CANARY: "🐤",
            ActionType.GENERATE_PROXY: "🔧",
            ActionType.SUGGEST_ACQUISITION: "📦",
            ActionType.ASK_OPERATOR: "❓",
            ActionType.REPORT: "📋",
        }.get(action.action_type, "•")

        console.print(f"  {icon} [bold]{action.action_type.value}[/] {json.dumps(action.params, default=str)[:100]}")
        if action.reasoning:
            console.print(f"     [dim]{action.reasoning[:120]}[/dim]")

    def _display_report(self, report: dict):
        """Display final findings report."""
        table = Table(title="Lacuna Findings")
        table.add_column("DLL", style="cyan")
        table.add_column("Host EXE", style="green")
        table.add_column("Type", style="yellow")
        table.add_column("Status", style="bold")
        table.add_column("Novel?", style="magenta")

        for finding in report.get("findings", []):
            table.add_row(
                finding.get("dll", ""),
                finding.get("exe", ""),
                finding.get("type", ""),
                finding.get("status", ""),
                "YES" if finding.get("novel") else "no",
            )

        console.print(table)

        if report.get("recommendations"):
            console.print("\n[bold]Recommendations:[/]")
            for rec in report["recommendations"]:
                console.print(f"  • {rec}")

    def _generate_final_report(self) -> dict:
        """Generate report from accumulated state."""
        return {
            "findings": [
                {
                    "dll": c.dll_name,
                    "exe": c.target.name,
                    "type": c.hijack_type.value,
                    "status": c.status.value,
                    "novel": not c.is_on_hijacklibs,
                }
                for c in self.confirmed
            ],
            "total_scanned": len(self.agent.state.targets_scanned),
            "total_candidates": len(self.all_candidates),
            "confirmed": len(self.confirmed),
        }
