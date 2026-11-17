import os
from typing import Optional, Set, List
from mcp_servermigrate.core.models import MigrationPlan, InstallStrategy
from mcp_servermigrate.core.ssh_client import SSHConnection
from mcp_servermigrate.modules.lineage import LineageManager
from rich.console import Console

console = Console()

ALL_STAGES = {
    "modules",
    "groups",
    "packages",
    "staging",
    "binaries",
    "data_files",
    "rbac",
    "profile_scripts",
    "crons",
    "lineage",
}


class MigrationExecutor:
    def __init__(
        self,
        plan: MigrationPlan,
        src_conn: SSHConnection,
        tgt_conn: SSHConnection,
        approved_stages: Optional[Set[str]] = None
    ):
        self.plan = plan
        self.src = src_conn
        self.tgt = tgt_conn
        self.approved_stages = approved_stages or ALL_STAGES

    def _should_run(self, stage: str) -> bool:
        return stage in self.approved_stages

    def execute_plan(self) -> None:
        console.print(f"[bold green]🚀 Initiating Migration (Generation {self.plan.generation}) to {self.plan.target_host}...[/bold green]")
        if self.plan.preloaded_recipes_used:
            console.print(f"[cyan]🧠 Preloaded recipes inherited from lineage:[/cyan] {', '.join(self.plan.preloaded_recipes_used)}")

        if self.plan.informational_pam_rules:
            console.print(
                f"[yellow]ℹ️  Informational only — {len(self.plan.informational_pam_rules)} PAM group.conf rule(s) "
                f"detected on source (not applied to target per access policy).[/yellow]"
            )

        # 0. Enable DNF Module Streams (BUG-13)
        if self._should_run("modules") and self.plan.module_streams:
            console.print("[cyan]0. Enabling DNF Module Streams on Target...[/cyan]")
            for ms in self.plan.module_streams:
                console.print(f"  📦 Enabling module stream: [bold]{ms.name}:{ms.stream}[/bold]")
                self.tgt.run_privileged(
                    f"dnf module reset -y '{ms.name}' 2>/dev/null || true && dnf module enable -y '{ms.name}:{ms.stream}'",
                    f"Enable module stream {ms.name}:{ms.stream}"
                )

        # 1. Create Custom Application & Role Groups on Target Server (⚡ Batched round-trip)
        if self._should_run("groups") and self.plan.groups_to_create:
            console.print(f"[cyan]1. Creating {len(self.plan.groups_to_create)} application role groups on Target (batch)...[/cyan]")
            group_cmds = [f"groupadd -r '{grp.name}' 2>/dev/null || true" for grp in self.plan.groups_to_create]
            self.tgt.run_privileged(" && ".join(group_cmds), "Create application role groups in batch")

        # 1b. Real `packages` Stage (dnf install FIRST before tarballs/binaries)
        if self._should_run("packages") and self.plan.packages_to_install:
            pkg_list = " ".join(f"'{p}'" for p in self.plan.packages_to_install)
            console.print(f"[cyan]1b. Installing {len(self.plan.packages_to_install)} candidate RPM packages via dnf...[/cyan]")
            self.tgt.run_privileged(
                f"dnf install -y {pkg_list}",
                "Install candidate RPM packages"
            )

        # 2. Prepare Staging & Target Directories (owned by root:tool_users, mode 2750, no world access)
        if self._should_run("staging"):
            console.print("[cyan]2. Preparing /opt/tools directory structure (2750 root:tool_users)...[/cyan]")
            self.tgt.run_privileged(
                "groupadd -r tool_users 2>/dev/null || true && "
                "mkdir -p /opt/tools/bin /usr/local/bin /tmp/mcp_staging && "
                "chown root:tool_users /opt/tools /opt/tools/bin && "
                "chmod 2750 /opt/tools /opt/tools/bin",
                "Create hardened tool paths"
            )

        # 3. Deploy Applications, Enforce 0750 root:tool_users, and Publish /usr/local/bin Symlinks
        if self._should_run("binaries"):
            console.print("[cyan]3. Deploying applications and CLI tools...[/cyan]")

            # Phase A: Concurrently download all remote archives in parallel on the target
            download_candidates = [
                app for app in self.plan.apps_to_install
                if app.strategy in (InstallStrategy.TARBALL_DOWNLOAD, InstallStrategy.PRELOADED_RECIPE) and app.download_url
            ]

            if download_candidates:
                console.print(f"  ⚡ Launching parallel downloads on target for: {', '.join([a.name for a in download_candidates])}...")
                dl_jobs = []
                for app in download_candidates:
                    tmp_archive = f"/tmp/mcp_staging/{app.name}_archive"
                    job = f"curl -fsSL -o '{tmp_archive}' -- '{app.download_url}'"
                    if app.checksum_url:
                        checksum_file = f"/tmp/mcp_staging/{app.name}.sha256"
                        job += f" && curl -fsSL -o '{checksum_file}' -- '{app.checksum_url}'"
                    dl_jobs.append(f"({job}) &")

                batch_download_cmd = " ".join(dl_jobs) + " wait"
                self.tgt.run_privileged(batch_download_cmd, "Parallel download upstream releases")

            # Phase B: Extract, stage byte-for-byte, hardlink, enforce 0750 root:tool_users, and symlink
            for app in self.plan.apps_to_install:
                target_bin = app.target_path if app.target_path.startswith("/opt/tools/bin") else f"/opt/tools/bin/{app.name}"

                # BUG-7: Handle Hard Links
                if app.strategy == InstallStrategy.HARDLINK and app.hardlink_of:
                    console.print(f"  🔗 Hardlinking [cyan]{app.name}[/cyan] -> [green]{app.hardlink_of}[/green]...")
                    self.tgt.run_privileged(
                        f"ln -f '{app.hardlink_of}' '{target_bin}'",
                        f"Hardlink {app.name} from {app.hardlink_of}"
                    )
                    # Publish symlink in /usr/local/bin
                    self.tgt.run_privileged(
                        f"ln -sfn '{target_bin}' '/usr/local/bin/{app.name}'",
                        f"Publish symlink /usr/local/bin/{app.name}"
                    )
                    continue

                if app.strategy in (InstallStrategy.TARBALL_DOWNLOAD, InstallStrategy.PRELOADED_RECIPE) and app.download_url:
                    console.print(f"  📦 Unpacking and configuring [green]{app.name}[/green] ({app.version})...")
                    tmp_archive = f"/tmp/mcp_staging/{app.name}_archive"

                    # SEC-5: Strict checksum verification — FAIL the stage on mismatch (no `|| true`)
                    if app.checksum_url:
                        checksum_file = f"/tmp/mcp_staging/{app.name}.sha256"
                        asset_pattern = app.checksum_asset or os.path.basename(app.download_url) or app.name
                        verify_cmd = (
                            f"cd /tmp/mcp_staging && "
                            f"grep -F '{asset_pattern}' '{checksum_file}' | awk '{{print $1 \"  {app.name}_archive\"}}' | sha256sum -c --status"
                        )
                        self.tgt.run_privileged(verify_cmd, f"Verify SHA256 checksum for {app.name}")

                    if app.archive_format == "zip":
                        self.tgt.run_privileged(
                            f"unzip -o -q '{tmp_archive}' -d '/tmp/mcp_staging/{app.name}_extracted' && "
                            f"find '/tmp/mcp_staging/{app.name}_extracted' -type f -name '{app.name}' -exec cp -f {{}} '{target_bin}' + && "
                            f"rm -rf '/tmp/mcp_staging/{app.name}_extracted' '{tmp_archive}'",
                            f"Unpack zip for {app.name}"
                        )
                    elif app.archive_format == "raw_binary":
                        self.tgt.run_privileged(f"mv -f '{tmp_archive}' '{target_bin}'", f"Install raw binary for {app.name}")
                    else:
                        self.tgt.run_privileged(
                            f"mkdir -p '/tmp/mcp_staging/{app.name}_extracted' && "
                            f"tar -xzf '{tmp_archive}' -C '/tmp/mcp_staging/{app.name}_extracted' && "
                            f"find '/tmp/mcp_staging/{app.name}_extracted' -type f -name '{app.name}' -exec cp -f {{}} '{target_bin}' + && "
                            f"rm -rf '/tmp/mcp_staging/{app.name}_extracted' '{tmp_archive}'",
                            f"Unpack tar.gz for {app.name}"
                        )
                else:
                    # Byte-for-byte binary copy from source
                    console.print(f"  🔄 Copying [yellow]{app.name}[/yellow] byte-for-byte from Source Server...")
                    raw_bytes = self.src.read_bytes(app.source_path)
                    self.tgt.write_bytes_privileged(
                        path=target_bin,
                        data=raw_bytes,
                        mode="0750",
                        owner="root",
                        group="tool_users"
                    )

                # Enforce 0750 root:tool_users (no world/everyone access), SELinux bin_t, and optional extra role ACL
                acl_cmd = f"setfacl -m 'g:{app.target_group}:rx' '{target_bin}' && " if app.target_group and app.target_group != "tool_users" else ""
                self.tgt.run_privileged(
                    f"chown root:tool_users '{target_bin}' && "
                    f"chmod 0750 '{target_bin}' && "
                    f"(chcon -t bin_t '{target_bin}' 2>/dev/null || true) && "
                    f"{acl_cmd}"
                    f"ln -sfn '{target_bin}' '/usr/local/bin/{app.name}'",
                    f"Publish {app.name} (0750 root:tool_users) and symlink to /usr/local/bin"
                )

            # Ensure any remaining planned symlinks exist
            for link_path, target_path in self.plan.symlinks_to_create.items():
                self.tgt.run_privileged(
                    f"ln -sfn '{target_path}' '{link_path}'",
                    f"Ensure symlink {link_path} -> {target_path}"
                )

        # 4. Deploy Script Data & Cron Dependency Files (with .mcpbak backup on overwrite)
        if self._should_run("data_files") and self.plan.data_files_to_sync:
            console.print("[cyan]4. Deploying script data and cron dependency files to Target...[/cyan]")
            for df in self.plan.data_files_to_sync:
                console.print(f"  📄 Syncing file: [bold]{df.source_path}[/bold] -> [bold]{df.target_path}[/bold]")
                try:
                    # Back up target file if it already exists before overwriting
                    self.tgt.run_privileged(
                        f"test -f '{df.target_path}' && cp -a '{df.target_path}' '{df.target_path}.mcpbak' || true",
                        f"Backup {df.target_path} before overwrite"
                    )
                    raw_bytes = self.src.read_bytes(df.source_path)
                    self.tgt.write_bytes_privileged(
                        path=df.target_path,
                        data=raw_bytes,
                        mode=df.mode or "0644",
                        owner=df.owner or "root",
                        group=df.group
                    )
                except Exception as e:
                    console.print(f"    [yellow]⚠️ Skipping {df.source_path}: {e}[/yellow]")

        # 5. Apply Decoupled POSIX ACL Baseline (NO PAM / /etc/security/group.conf edits)
        if self._should_run("rbac"):
            for rbac in self.plan.rbac_mappings:
                console.print(f"[cyan]5. Configuring POSIX ACL baseline for group '{rbac.local_group}' (no PAM edits)...[/cyan]")
                self.tgt.run_privileged(f"groupadd -r '{rbac.local_group}' 2>/dev/null || true", "Create local role group")
                self.tgt.run_privileged(f"setfacl -R -m 'g:{rbac.local_group}:{rbac.permissions}' '{rbac.target_path}'", "Apply POSIX ACL")
                self.tgt.run_privileged(f"setfacl -R -d -m 'g:{rbac.local_group}:{rbac.permissions}' '{rbac.target_path}'", "Apply Default ACL inheritance")

        # 6. Deploy Verified Profile Scripts (BUG-1: Parity over invention, no stock overwrites)
        if self._should_run("profile_scripts") and self.plan.profile_scripts_to_deploy:
            console.print("[cyan]6. Syncing verified non-stock profile scripts to /etc/profile.d/...[/cyan]")
            for script_path in self.plan.profile_scripts_to_deploy:
                script_name = os.path.basename(script_path)
                target_script = f"/etc/profile.d/{script_name}"
                console.print(f"  📜 Syncing profile script: [bold]{script_name}[/bold]")
                try:
                    script_content = self.src.read_text(script_path)
                    self.tgt.write_text_privileged(
                        path=target_script,
                        content=script_content,
                        mode="0644",
                        owner="root",
                        group="root"
                    )
                except Exception as e:
                    console.print(f"    [yellow]⚠️ Skipping {script_name}: {e}[/yellow]")

        # 7. Migrate Root Crontabs with Backup & Idempotency (BUG-10, BUG-15, BUG-16)
        if self._should_run("crons") and self.plan.root_crons_to_apply:
            console.print("[cyan]7. Applying root crontabs on Target (with backup)...[/cyan]")
            self.tgt.run_privileged(
                "crontab -l -u root > /etc/crontab.root.mcpbak 2>/dev/null || true",
                "Backup current root crontab to /etc/crontab.root.mcpbak"
            )

            existing_lines = set()
            try:
                raw_existing = self.tgt.run_privileged("crontab -l -u root 2>/dev/null", "Read target crontab").splitlines()
                existing_lines = {l.strip() for l in raw_existing if l.strip()}
            except Exception:
                pass

            new_lines = list(existing_lines)
            for c in self.plan.root_crons_to_apply:
                c_line = c.line.strip()
                if c_line and c_line not in existing_lines:
                    new_lines.append(c_line)

            merged_crontab = "\n".join(new_lines) + "\n"
            staging_cron = "/tmp/mcp_staging_root_cron"
            self.tgt.write_text_privileged(
                path=staging_cron,
                content=merged_crontab,
                mode="0600",
                owner="root",
                group="root"
            )
            self.tgt.run_privileged(
                f"crontab -u root '{staging_cron}' && rm -f '{staging_cron}'",
                "Apply merged root crontab"
            )

        # 8. Plant Migration Lineage Manifest & Operational Skill on Target (BUG-21)
        if self._should_run("lineage") and self.plan.manifest_to_plant:
            console.print("[cyan]8. Planting on-server Migration Skill and Lineage Manifest at /etc/mcp-migration/...[/cyan]")
            LineageManager.plant_lineage(self.tgt, self.plan.manifest_to_plant)

        console.print("[bold green]✅ Migration execution, group creation, and lineage recording completed successfully![/bold green]")
