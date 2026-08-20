from mcp_servermigrate.core.ssh_client import SSHConnection
from rich.console import Console

console = Console()

class PostFlightVerifier:
    def __init__(self, target_conn: SSHConnection):
        self.tgt = target_conn

    def verify(self) -> dict:
        console.print("[bold yellow]🔍 Running Post-Flight Verification on Target Server...[/bold yellow]")
        results = {}

        avc_check = self.tgt.run_sudo_cmd("ausearch -m avc -ts recent 2>/dev/null | grep -i denied || true", "Audit SELinux denials")
        results["selinux_denials_found"] = bool(avc_check.strip())

        ports = self.tgt.run_cmd("ss -tulpn 2>/dev/null").splitlines()
        results["open_sockets_count"] = max(0, len(ports) - 1)

        acl_check = self.tgt.run_cmd("getfacl /opt/tools 2>/dev/null")
        results["tools_acl_configured"] = "tool_users" in acl_check

        return results
