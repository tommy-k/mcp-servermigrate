import typer
from rich.console import Console
from mcp_servermigrate.core.security import EphemeralCredentialVault
from mcp_servermigrate.core.ssh_client import SSHConnection
from mcp_servermigrate.modules.discovery import DiscoveryEngine
from mcp_servermigrate.modules.planner import MigrationPlanner
from mcp_servermigrate.modules.executor import MigrationExecutor
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
    auto_approve_sudo: bool = typer.Option(False, "--auto-approve-sudo", help="Bypass interactive sudo prompts")
):
    """Run full migration between Source and Target."""
    EphemeralCredentialVault.get_vault().set_auto_approve(auto_approve_sudo)

    src_conn = SSHConnection(host=source, user=user)
    tgt_conn = SSHConnection(host=target, user=user)

    console.print(f"[bold cyan]🔍 Auditing Source ({source}) and Target ({target})...[/bold cyan]")
    src_state = DiscoveryEngine(src_conn).discover_state()
    tgt_state = DiscoveryEngine(tgt_conn).discover_state()

    planner = MigrationPlanner(src_state, tgt_state)
    plan = planner.generate_plan()
    console.print_json(plan.model_dump_json())

    executor = MigrationExecutor(plan, src_conn, tgt_conn)
    executor.execute_plan()

    verifier = PostFlightVerifier(tgt_conn)
    results = verifier.verify()
    console.print(f"[bold green]Post-Flight Verification:[/bold green] {results}")

    src_conn.close()
    tgt_conn.close()

if __name__ == "__main__":
    app()
