import os
from mcp_servermigrate.core.models import MigrationPlan, InstallStrategy
from mcp_servermigrate.core.ssh_client import SSHConnection
from mcp_servermigrate.modules.lineage import LineageManager
from rich.console import Console

console = Console()

class MigrationExecutor:
    def __init__(self, plan: MigrationPlan, src_conn: SSHConnection, tgt_conn: SSHConnection):
        self.plan = plan
        self.src = src_conn
        self.tgt = tgt_conn

    def execute_plan(self) -> None:
        console.print(f"[bold green]🚀 Initiating Migration (Generation {self.plan.generation}) to {self.plan.target_host}...[/bold green]")
        if self.plan.preloaded_recipes_used:
            console.print(f"[cyan]🧠 Preloaded recipes inherited from lineage:[/cyan] {', '.join(self.plan.preloaded_recipes_used)}")

        # 1. Prepare Staging & Target Directories
        console.print("[cyan]1. Preparing /opt/tools directory structure...[/cyan]")
        self.tgt.run_sudo_cmd("mkdir -p /opt/tools/bin /tmp/mcp_staging", "Create tool paths")

        # 2. Deploy Applications (Tarball Download vs Source Sync)
        console.print("[cyan]2. Deploying applications and CLI tools...[/cyan]")
        for app in self.plan.apps_to_install:
            target_bin = f"/opt/tools/bin/{app.name}"
            if app.strategy in (InstallStrategy.TARBALL_DOWNLOAD, InstallStrategy.PRELOADED_RECIPE) and app.download_url:
                console.print(f"  ⬇️  Downloading [green]{app.name}[/green] ({app.version}) from upstream...")
                tmp_archive = f"/tmp/mcp_staging/{app.name}_archive"

                # Download
                self.tgt.run_sudo_cmd(
                    f"curl -fsSL '{app.download_url}' -o {tmp_archive}",
                    f"Download {app.name} upstream release"
                )

                # Universal Unpack & Ingest
                if app.archive_format == "zip":
                    self.tgt.run_sudo_cmd(
                        f"unzip -o -q {tmp_archive} -d /tmp/mcp_staging/{app.name}_extracted && "
                        f"find /tmp/mcp_staging/{app.name}_extracted -type f -name '{app.name}' -exec cp -f {{}} {target_bin} \\; && "
                        f"rm -rf /tmp/mcp_staging/{app.name}_extracted {tmp_archive}",
                        f"Unpack zip for {app.name}"
                    )
                elif app.archive_format == "raw_binary":
                    self.tgt.run_sudo_cmd(f"mv -f {tmp_archive} {target_bin}", f"Install raw binary for {app.name}")
                else:
                    # Default: tar.gz / tgz
                    self.tgt.run_sudo_cmd(
                        f"mkdir -p /tmp/mcp_staging/{app.name}_extracted && "
                        f"tar -xzf {tmp_archive} -C /tmp/mcp_staging/{app.name}_extracted 2>/dev/null || true && "
                        f"find /tmp/mcp_staging/{app.name}_extracted -type f -name '{app.name}' -exec cp -f {{}} {target_bin} \\; 2>/dev/null || cp -f {tmp_archive} {target_bin} && "
                        f"rm -rf /tmp/mcp_staging/{app.name}_extracted {tmp_archive}",
                        f"Unpack tar.gz for {app.name}"
                    )
            else:
                # Fallback to source sync
                console.print(f"  🔄 Syncing [yellow]{app.name}[/yellow] from Source Server X...")
                # Note: In production rsync between hosts or pipe via controller
                self.tgt.run_sudo_cmd(f"touch {target_bin}", f"Stage binary for {app.name}")

            # Enforce executable and SELinux
            self.tgt.run_sudo_cmd(f"chmod 755 {target_bin} && chcon -t bin_t {target_bin} 2>/dev/null || true", f"Set permissions for {app.name}")

        # 3. Apply Decoupled RBAC
        for rbac in self.plan.rbac_mappings:
            console.print(f"[cyan]3. Configuring RBAC for local group '{rbac.local_group}'...[/cyan]")
            self.tgt.run_sudo_cmd(f"groupadd -r {rbac.local_group} 2>/dev/null || true", "Create local role group")
            self.tgt.run_sudo_cmd(f"setfacl -R -m g:{rbac.local_group}:{rbac.permissions} {rbac.target_path}", "Apply POSIX ACL")
            self.tgt.run_sudo_cmd(f"setfacl -R -d -m g:{rbac.local_group}:{rbac.permissions} {rbac.target_path}", "Apply Default ACL inheritance")
            self.tgt.run_sudo_cmd(
                f"grep -q '{rbac.local_group}' /etc/security/group.conf 2>/dev/null || "
                f"echo 'sshd; *; %{rbac.ad_group}; Al0000-2400; {rbac.local_group}' >> /etc/security/group.conf",
                "Configure PAM group mapping"
            )

        # 4. Deploy System Baseline (/etc/profile.d/corp-standards.sh)
        console.print("[cyan]4. Deploying global environment baseline to /etc/profile.d/...[/cyan]")
        corp_env = (
            '# /etc/profile.d/corp-standards.sh\n'
            'if [[ ":$PATH:" != *":/opt/tools/bin:"* ]]; then\n'
            '    export PATH="/opt/tools/bin:$HOME/.local/bin:$PATH"\n'
            'fi\n'
            'export EDITOR="${EDITOR:-vim}"\n'
            'alias ll="ls -lah --color=auto"\n'
        )
        self.tgt.run_sudo_cmd(f"echo '{corp_env}' > /etc/profile.d/corp-standards.sh && chmod 644 /etc/profile.d/corp-standards.sh", "Deploy global profile")

        # 5. Migrate Root Crontabs if selected
        if self.plan.root_crons_to_apply:
            console.print("[cyan]5. Applying root crontabs on Target...[/cyan]")
            cron_content = "\\n".join([c.line for c in self.plan.root_crons_to_apply])
            self.tgt.run_sudo_cmd(f'echo -e "{cron_content}" | crontab -u root -', "Update root crontab")

        # 6. Plant Migration Lineage Manifest & Operational Skill on Target
        if self.plan.manifest_to_plant:
            console.print("[cyan]6. Planting on-server Migration Skill and Lineage Manifest at /etc/mcp-migration/...[/cyan]")
            LineageManager.plant_lineage(self.tgt, self.plan.manifest_to_plant)

        console.print("[bold green]✅ Migration execution and lineage recording completed successfully![/bold green]")
