from mcp_servermigrate.core.models import MigrationPlan
from mcp_servermigrate.core.ssh_client import SSHConnection
from rich.console import Console

console = Console()

class MigrationExecutor:
    def __init__(self, plan: MigrationPlan, src_conn: SSHConnection, tgt_conn: SSHConnection):
        self.plan = plan
        self.src = src_conn
        self.tgt = tgt_conn

    def execute_plan(self) -> None:
        console.print(f"[bold green]🚀 Initiating Migration to {self.plan.target_host}...[/bold green]")

        console.print("[cyan]1. Preparing /opt/tools staging directory...[/cyan]")
        self.tgt.run_sudo_cmd("mkdir -p /opt/tools/bin", "Create tool path")

        for rbac in self.plan.rbac_mappings:
            console.print(f"[cyan]2. Configuring RBAC for local group '{rbac.local_group}'...[/cyan]")
            self.tgt.run_sudo_cmd(f"groupadd -r {rbac.local_group} 2>/dev/null || true", "Create local role group")
            self.tgt.run_sudo_cmd(f"setfacl -R -m g:{rbac.local_group}:{rbac.permissions} {rbac.target_path}", "Apply POSIX ACL")
            self.tgt.run_sudo_cmd(f"setfacl -R -d -m g:{rbac.local_group}:{rbac.permissions} {rbac.target_path}", "Apply Default ACL inheritance")
            self.tgt.run_sudo_cmd(
                f"grep -q '{rbac.local_group}' /etc/security/group.conf 2>/dev/null || "
                f"echo 'sshd; *; %{rbac.ad_group}; Al0000-2400; {rbac.local_group}' >> /etc/security/group.conf",
                "Configure PAM group mapping"
            )

        console.print("[cyan]3. Deploying global environment baseline to /etc/profile.d/...[/cyan]")
        corp_env = (
            '# /etc/profile.d/corp-standards.sh\n'
            'if [[ ":$PATH:" != *":/opt/tools/bin:"* ]]; then\n'
            '    export PATH="/opt/tools/bin:$HOME/.local/bin:$PATH"\n'
            'fi\n'
            'export EDITOR="${EDITOR:-vim}"\n'
            'alias ll="ls -lah --color=auto"\n'
        )
        self.tgt.run_sudo_cmd(f"echo '{corp_env}' > /etc/profile.d/corp-standards.sh && chmod 644 /etc/profile.d/corp-standards.sh", "Deploy global profile")

        if self.plan.root_crons_to_apply:
            console.print("[cyan]4. Applying root crontabs on Target...[/cyan]")
            cron_content = "\\n".join([c.line for c in self.plan.root_crons_to_apply])
            self.tgt.run_sudo_cmd(f'echo -e "{cron_content}" | crontab -u root -', "Update root crontab")

        console.print("[bold green]✅ Migration execution completed![/bold green]")
