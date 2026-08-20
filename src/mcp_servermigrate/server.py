from mcp.server.fastmcp import FastMCP
from mcp_servermigrate.core.ssh_client import SSHConnection
from mcp_servermigrate.modules.discovery import DiscoveryEngine
from mcp_servermigrate.modules.planner import MigrationPlanner
from mcp_servermigrate.modules.executor import MigrationExecutor
from mcp_servermigrate.modules.verifier import PostFlightVerifier

mcp = FastMCP("Server-Migrate-Agent")

@mcp.tool()
def audit_host(host: str, user: str = "root") -> str:
    """Inspects a RHEL/Fedora host and returns structured JSON telemetry."""
    conn = SSHConnection(host=host, user=user)
    engine = DiscoveryEngine(conn)
    state = engine.discover_state()
    conn.close()
    return state.model_dump_json(indent=2)

@mcp.tool()
def create_migration_plan(source_host: str, target_host: str, user: str = "root") -> str:
    """Performs gap analysis between Source and Target servers and generates a Migration Plan."""
    src_conn = SSHConnection(host=source_host, user=user)
    tgt_conn = SSHConnection(host=target_host, user=user)
    
    src_state = DiscoveryEngine(src_conn).discover_state()
    tgt_state = DiscoveryEngine(tgt_conn).discover_state()
    
    src_conn.close()
    tgt_conn.close()
    
    planner = MigrationPlanner(src_state, tgt_state)
    plan = planner.generate_plan()
    return plan.model_dump_json(indent=2)

@mcp.tool()
def execute_migration(source_host: str, target_host: str, user: str = "root") -> str:
    """Executes the migration plan against the target server with safety confirmation gates."""
    src_conn = SSHConnection(host=source_host, user=user)
    tgt_conn = SSHConnection(host=target_host, user=user)
    
    src_state = DiscoveryEngine(src_conn).discover_state()
    tgt_state = DiscoveryEngine(tgt_conn).discover_state()
    
    plan = MigrationPlanner(src_state, tgt_state).generate_plan()
    executor = MigrationExecutor(plan, src_conn, tgt_conn)
    executor.execute_plan()
    
    verifier = PostFlightVerifier(tgt_conn)
    results = verifier.verify()
    
    src_conn.close()
    tgt_conn.close()
    return f"Migration completed! Verification results: {results}"
