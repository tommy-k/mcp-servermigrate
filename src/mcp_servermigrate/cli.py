import os
from typing import Optional, List
import typer
from rich.console import Console
from mcp_servermigrate.core.security import EphemeralCredentialVault
from mcp_servermigrate.core.ssh_client import SSHConnection
from mcp_servermigrate.modules.discovery import DiscoveryEngine
from mcp_servermigrate.modules.planner import MigrationPlanner
from mcp_servermigrate.modules.executor import MigrationExecutor, ALL_STAGES
from mcp_servermigrate.modules.verifier import PostFlightVerifier

app = typer.Typer(help="CLI for Enterprise Linux Server Migration Agent (RHEL, Rocky, Alma, Fedora)")
console = Console()

@app.command()
def audit(host: str, user: str = "root"):
    """Discover and audit a single server."""
    conn = SSHConnection(host=host, user=user)
    engine = DiscoveryEngine(conn)
    state = engine.discover_state()
    conn.close()
    console.print_json(state.model_dump_json())

@app.command()
def migrate(
    source: str = typer.Option(..., help="Source Server hostname/IP"),
    target: str = typer.Option(..., help="Target Server hostname/IP"),
    user: str = typer.Option("root", help="SSH username"),
    auto_approve_sudo: bool = typer.Option(False, "--auto-approve-sudo", help="Bypass interactive sudo prompts"),
    sudo_pass_file: Optional[str] = typer.Option(None, "--sudo-pass-file", help="Path to 0600 sudo password file"),
    approve_stages: Optional[str] = typer.Option(None, "--approve-stages", help="Comma-separated stages to run (e.g. groups,binaries,crons,acls,lineage,data_files)"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Generate migration plan without executing")
):
    """Run full migration between Source and Target."""
    vault = EphemeralCredentialVault.get_vault()
    vault.set_auto_approve(auto_approve_sudo)

    if sudo_pass_file:
        vault.load_sudo_pass_file(sudo_pass_file)

    approved_stages_set = None
    if approve_stages:
        stages = [s.strip().lower() for s in approve_stages.split(",") if s.strip()]
        approved_stages_set = set(stages)
        unknown = approved_stages_set - ALL_STAGES
        if unknown:
            console.print(f"[bold red]Unknown stages: {', '.join(unknown)}. Valid stages: {', '.join(sorted(ALL_STAGES))}[/bold red]")
            raise typer.Exit(code=1)

    src_conn = SSHConnection(host=source, user=user)
    tgt_conn = SSHConnection(host=target, user=user)

    console.print(f"[bold cyan]🔍 Auditing Source ({source}) and Target ({target})...[/bold cyan]")
    src_state = DiscoveryEngine(src_conn).discover_state()
    tgt_state = DiscoveryEngine(tgt_conn).discover_state()

    planner = MigrationPlanner(src_state, tgt_state, src_ssh=src_conn, tgt_ssh=tgt_conn)
    plan = planner.generate_plan()
    console.print_json(plan.model_dump_json())

    if dry_run:
        console.print("[yellow]Dry-run requested. Skipping execution.[/yellow]")
        src_conn.close()
        tgt_conn.close()
        return

    executor = MigrationExecutor(plan, src_conn, tgt_conn, approved_stages=approved_stages_set)
    executor.execute_plan()

    verifier = PostFlightVerifier(tgt_conn)
    published = [a.name for a in plan.apps_to_install]
    results = verifier.verify(published_tools=published)
    console.print(f"[bold green]Post-Flight Verification:[/bold green] {results}")

    src_conn.close()
    tgt_conn.close()

if __name__ == "__main__":
    app()
