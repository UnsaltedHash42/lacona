"""Lacuna CLI — entry point for standalone operation."""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

from rich.console import Console

console = Console()


def main():
    parser = argparse.ArgumentParser(
        prog="lacuna",
        description="Agentic DLL hijack discovery tool",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--api-key", help="Anthropic API key (or set ANTHROPIC_API_KEY)")
    parser.add_argument("--model", default="claude-sonnet-4-20250514", help="Model to use")
    parser.add_argument("-o", "--output", type=Path, default=Path("./lacuna_output"), help="Output directory")
    parser.add_argument("--non-interactive", action="store_true", help="Skip operator prompts")

    sub = parser.add_subparsers(dest="command")

    # --- hunt: full agentic loop ---
    hunt_p = sub.add_parser("hunt", help="Run full agentic hijack discovery")
    hunt_p.add_argument("--context", help="Target org/environment context for the agent")
    hunt_p.add_argument("--max-iter", type=int, default=50, help="Max agent iterations")

    # --- scan: one-shot static scan ---
    scan_p = sub.add_parser("scan", help="Static scan a directory or binary")
    scan_p.add_argument("target", type=Path, help="Directory or PE file to scan")
    scan_p.add_argument("--recursive", action="store_true", default=True)
    scan_p.add_argument("--score", action="store_true", default=True, help="Enable scoring (default)")
    scan_p.add_argument("--no-score", action="store_true", help="Disable scoring")
    scan_p.add_argument("--min-score", type=int, default=0, help="Only show candidates above this score")
    scan_p.add_argument("--format", choices=["table", "json"], default="table", help="Output format")

    # --- dynamic: procmon capture ---
    dyn_p = sub.add_parser("dynamic", help="Dynamic monitoring via procmon")
    dyn_p.add_argument("target", type=Path, help="Target executable")
    dyn_p.add_argument("--duration", type=int, default=15, help="Capture duration (seconds)")
    dyn_p.add_argument("--procmon", type=Path, help="Path to Procmon64.exe")

    # --- proxy: generate proxy DLL ---
    proxy_p = sub.add_parser("proxy", help="Generate proxy DLL source")
    proxy_p.add_argument("dll", type=Path, help="Target DLL to proxy")
    proxy_p.add_argument("--forward-name", help="Name for renamed original (default: <stem>_orig.dll)")

    # --- suggest: list acquisition targets ---
    suggest_p = sub.add_parser("suggest", help="Suggest software to install for scanning")
    suggest_p.add_argument("--category", help="Filter by category (rmm, backup, vpn, etc.)")
    suggest_p.add_argument("--system-only", action="store_true", help="Only SYSTEM-context targets")

    # --- validate: remote validation of findings ---
    validate_p = sub.add_parser("validate", help="Remote validation of scan findings")
    validate_p.add_argument("--target", required=True, help="Remote host (IP or hostname)")
    validate_p.add_argument("--user", required=True, help="Username")
    validate_p.add_argument("--password", help="Password (or use --key)")
    validate_p.add_argument("--key", type=Path, help="SSH private key")
    validate_p.add_argument("--transport", choices=["winrm", "ssh"], default="winrm")
    validate_p.add_argument("--port", type=int, help="Override port")
    validate_p.add_argument("--findings", type=Path, required=True, help="JSON from scan output")
    validate_p.add_argument("--max-parallel", type=int, default=1, help="Parallel validations")
    validate_p.add_argument("--filter-score", type=int, help="Only validate above this score")
    validate_p.add_argument("--timeout", type=int, default=30, help="Timeout per validation (s)")
    validate_p.add_argument("--dry-run", action="store_true", help="Show plan without executing")

    # --- canary: compile and test a canary DLL ---
    canary_p = sub.add_parser("canary", help="Build and deploy a canary DLL")
    canary_p.add_argument("dll_name", help="DLL name to impersonate")
    canary_p.add_argument("plant_path", type=Path, help="Directory to plant canary in")
    canary_p.add_argument("--host-exe", default="unknown.exe", help="Host executable name")
    canary_p.add_argument("--arch", choices=["x86", "x64"], default="x64")

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )

    if args.command is None:
        parser.print_help()
        return

    # Route to subcommand
    if args.command == "hunt":
        _cmd_hunt(args)
    elif args.command == "scan":
        _cmd_scan(args)
    elif args.command == "dynamic":
        _cmd_dynamic(args)
    elif args.command == "proxy":
        _cmd_proxy(args)
    elif args.command == "suggest":
        _cmd_suggest(args)
    elif args.command == "canary":
        _cmd_canary(args)
    elif args.command == "validate":
        _cmd_validate(args)


def _cmd_hunt(args):
    from lacuna.agent import LacunaAgent
    from lacuna.orchestrator import Orchestrator

    api_key = args.api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        console.print("[red]Error:[/] Set ANTHROPIC_API_KEY or pass --api-key")
        sys.exit(1)

    agent = LacunaAgent(api_key=api_key, model=args.model)
    orch = Orchestrator(agent, work_dir=args.output)
    orch.max_iterations = args.max_iter
    orch.interactive = not args.non_interactive

    result = orch.run(initial_context=args.context)

    # Save report
    import json
    report_path = args.output / "report.json"
    report_path.write_text(json.dumps(result, indent=2, default=str))
    console.print(f"\n[green]Report saved:[/] {report_path}")


def _cmd_scan(args):
    import json as json_mod

    from lacuna.modules.hijacklibs import novelty_check
    from lacuna.modules.scorer import score_candidates
    from lacuna.modules.static_analyzer import analyze_binary, scan_directory

    target = args.target
    if target.is_dir():
        candidates = scan_directory(target, recursive=args.recursive)
    elif target.is_file():
        candidates = analyze_binary(target)
    else:
        console.print(f"[red]Error:[/] {target} not found")
        sys.exit(1)

    # Enrich novelty
    for c in candidates:
        check = novelty_check(c.dll_name, c.target.name)
        c.is_on_hijacklibs = not check["is_novel"]

    # Scoring
    use_score = args.score and not args.no_score
    if use_score:
        candidates = score_candidates(candidates)
        if args.min_score > 0:
            candidates = [c for c in candidates if c.score >= args.min_score]

    # JSON output
    if args.format == "json":
        output = []
        for c in candidates:
            # If the DLL actually lives alongside the host, emit its path so the
            # remote validator backs up + restores. Otherwise (phantom / not
            # co-located), leave dll_path null — validator drops the canary
            # alongside the host without backup.
            sibling = c.target.path.parent / c.dll_name
            dll_path = str(sibling) if sibling.exists() else None

            entry = {
                "host_exe": c.target.name,
                "host_path": str(c.target.path),
                "dll_name": c.dll_name,
                "dll_path": dll_path,
                "hijack_type": c.hijack_type.value,
                "discovery_method": c.discovery_method,
                "confidence": c.confidence,
                "is_novel": not c.is_on_hijacklibs,
                "is_signed": c.target.is_signed,
            }
            if use_score:
                entry["score"] = c.score
                entry["score_breakdown"] = c.score_breakdown
            output.append(entry)

        json_str = json_mod.dumps(output, indent=2, default=str)
        if args.output and args.output != Path("./lacuna_output"):
            args.output.mkdir(parents=True, exist_ok=True)
            out_file = args.output / "scan_results.json"
            out_file.write_text(json_str)
            console.print(f"[green]Written:[/] {out_file}")
        else:
            console.print(json_str)
        return

    # Table output
    from rich.table import Table
    title = f"Static Scan: {target}"
    if use_score and args.min_score > 0:
        title += f" (min-score: {args.min_score})"
    table = Table(title=title)
    table.add_column("Host EXE", style="green")
    table.add_column("DLL", style="cyan")
    table.add_column("Type", style="yellow")
    table.add_column("Discovery", style="dim")
    table.add_column("Novel?", style="magenta")
    if use_score:
        table.add_column("Score", justify="right")

    for c in candidates:
        novel_str = "YES" if not c.is_on_hijacklibs else "no"
        score_str = ""
        if use_score:
            if c.score >= 70:
                score_str = f"[bold red]{int(c.score)}[/bold red]"
            elif c.score >= 40:
                score_str = f"[yellow]{int(c.score)}[/yellow]"
            else:
                score_str = f"[dim]{int(c.score)}[/dim]"

        row = [
            c.target.name,
            c.dll_name,
            c.hijack_type.value,
            c.discovery_method,
            novel_str,
        ]
        if use_score:
            row.append(score_str)
        table.add_row(*row)

    console.print(table)
    console.print(f"\nTotal: {len(candidates)} candidates")


def _cmd_dynamic(args):
    from lacuna.modules.dynamic_monitor import parse_procmon_csv, run_procmon_capture

    csv_path = run_procmon_capture(
        args.target,
        procmon_path=args.procmon,
        duration_seconds=args.duration,
    )
    if csv_path is None:
        console.print("[red]Procmon capture failed[/]")
        sys.exit(1)

    phantoms = parse_procmon_csv(csv_path)
    console.print(f"\n[bold]Phantom DLLs (NAME NOT FOUND):[/]")
    for p in phantoms:
        console.print(f"  {p['dll_name']:30} attempted: {p['path_attempted']}")


def _cmd_proxy(args):
    from lacuna.modules.proxy_generator import write_proxy_project

    if not args.dll.exists():
        console.print(f"[red]Error:[/] DLL not found: {args.dll}")
        sys.exit(1)

    output_dir = Path("./lacuna_output/proxies") / args.dll.stem
    files = write_proxy_project(args.dll, output_dir, forward_dll_name=args.forward_name)

    console.print(f"[green]Proxy project generated:[/] {output_dir}")
    for name, path in files.items():
        console.print(f"  {name}: {path}")


def _cmd_suggest(args):
    from lacuna.modules.target_acquisition import format_suggestions, get_suggestions

    suggestions = get_suggestions(
        category_filter=args.category,
        system_only=args.system_only,
    )
    console.print(format_suggestions(suggestions))


def _cmd_canary(args):
    from lacuna.modules.canary import compile_canary, generate_canary_source

    breadcrumb_dir = args.output if hasattr(args, "output") else Path("./lacuna_output/breadcrumbs")
    breadcrumb_dir.mkdir(parents=True, exist_ok=True)

    source = generate_canary_source(args.dll_name, args.host_exe, breadcrumb_dir)
    output_path = Path("./lacuna_output/canaries") / args.dll_name
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if compile_canary(source, output_path, arch=args.arch):
        console.print(f"[green]Canary compiled:[/] {output_path}")
        console.print(f"[dim]Deploy to: {args.plant_path / args.dll_name}[/dim]")
    else:
        console.print("[red]Canary compilation failed[/]")
        console.print("[dim]Is mingw installed? brew install mingw-w64 / apt install mingw-w64[/dim]")


def _cmd_validate(args):
    import json as json_mod

    from lacuna.modules.canary import compile_canary, generate_canary_source
    from lacuna.modules.remote_validator import RemoteValidator, ValidationTarget

    # Load findings
    if not args.findings.exists():
        console.print(f"[red]Error:[/] Findings file not found: {args.findings}")
        sys.exit(1)

    findings = json_mod.loads(args.findings.read_text())
    if not isinstance(findings, list):
        console.print("[red]Error:[/] Findings file must be a JSON array")
        sys.exit(1)

    # Filter by score if requested
    if args.filter_score:
        findings = [f for f in findings if f.get("score", 0) >= args.filter_score]

    if not findings:
        console.print("[yellow]No candidates to validate after filtering.[/]")
        return

    console.print(
        f"\n[bold]Remote Validation: {args.target} ({args.transport})[/bold]"
    )
    console.print(f"Candidates: {len(findings)}\n")

    # Dry-run mode
    if args.dry_run:
        from rich.table import Table
        table = Table(title="Dry Run — Would Validate")
        table.add_column("Host EXE", style="green")
        table.add_column("DLL", style="cyan")
        table.add_column("Score", justify="right")
        for f in findings:
            table.add_row(
                Path(f.get("host_path", "")).name or f.get("host_exe", "?"),
                f["dll_name"],
                str(f.get("score", "—")),
            )
        console.print(table)
        return

    # Compile canary DLLs
    canary_dir = args.output / "canaries" / "validate"
    canary_dir.mkdir(parents=True, exist_ok=True)
    breadcrumb_dir = Path(r"C:\Temp\lacuna\breadcrumbs")

    console.print("[dim]Compiling canary DLLs...[/dim]")
    for f in findings:
        dll_name = f["dll_name"]
        canary_path = canary_dir / dll_name
        if not canary_path.exists():
            source = generate_canary_source(
                dll_name,
                Path(f.get("host_path", "unknown.exe")).name,
                breadcrumb_dir,
            )
            if not compile_canary(source, canary_path):
                console.print(f"[yellow]Warning:[/] Failed to compile canary for {dll_name}")

    # Connect and validate
    target = ValidationTarget(
        host=args.target,
        username=args.user,
        password=args.password,
        key_path=str(args.key) if args.key else None,
        transport=args.transport,
        port=args.port,
    )

    validator = RemoteValidator(target)
    try:
        validator.connect()
        results = validator.validate_batch(findings, canary_dir)
    finally:
        validator.disconnect()

    # Display results
    from rich.table import Table
    table = Table(title=f"Remote Validation: {args.target} ({args.transport})")
    table.add_column("Host EXE", style="green")
    table.add_column("DLL", style="cyan")
    table.add_column("Loaded?", justify="center")
    table.add_column("Survived?", justify="center")
    table.add_column("Time", justify="right", style="dim")

    success_count = 0
    for r in results:
        loaded = "[bold green]YES[/bold green]" if r.success else "[red]NO[/red]"
        survived = (
            "[bold green]YES[/bold green]" if r.process_survived
            else "[dim]N/A[/dim]" if not r.success
            else "[yellow]NO[/yellow]"
        )
        table.add_row(
            r.host_exe,
            r.candidate_dll,
            loaded,
            survived,
            f"{r.duration_seconds:.1f}s",
        )
        if r.success:
            success_count += 1

    console.print(table)
    total_time = sum(r.duration_seconds for r in results)
    console.print(
        f"\nValidated: {success_count}/{len(results)} | "
        f"Failed: {len(results) - success_count} | "
        f"Duration: {total_time:.0f}s"
    )

    # Save results
    output_path = args.output / "validation_results.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_data = [
        {
            "candidate_dll": r.candidate_dll,
            "host_exe": r.host_exe,
            "success": r.success,
            "process_survived": r.process_survived,
            "breadcrumb_content": r.breadcrumb_content,
            "error": r.error,
            "duration_seconds": r.duration_seconds,
            "restore_verified": r.restore_verified,
            "notes": r.notes,
        }
        for r in results
    ]
    output_path.write_text(json_mod.dumps(output_data, indent=2))
    console.print(f"[green]Results saved:[/] {output_path}")


if __name__ == "__main__":
    main()
