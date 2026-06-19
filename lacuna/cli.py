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
    from lacuna.modules.hijacklibs import novelty_check
    from lacuna.modules.static_analyzer import analyze_binary, scan_directory

    target = args.target
    if target.is_dir():
        candidates = scan_directory(target, recursive=args.recursive)
    elif target.is_file():
        candidates = analyze_binary(target)
    else:
        console.print(f"[red]Error:[/] {target} not found")
        sys.exit(1)

    # Display results
    from rich.table import Table
    table = Table(title=f"Static Scan: {target}")
    table.add_column("Host EXE", style="green")
    table.add_column("DLL", style="cyan")
    table.add_column("Type", style="yellow")
    table.add_column("Novel?", style="magenta")

    for c in sorted(candidates, key=lambda x: x.dll_name):
        check = novelty_check(c.dll_name, c.target.name)
        table.add_row(
            c.target.name,
            c.dll_name,
            c.hijack_type.value,
            "YES" if check["is_novel"] else f"no ({check['reason'][:40]})",
        )

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


if __name__ == "__main__":
    main()
