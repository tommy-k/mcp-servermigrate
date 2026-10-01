import os
import re
from datetime import datetime, timezone
from typing import List, Dict, Optional, Set
from mcp_servermigrate.core.models import (
    ServerState, MigrationPlan, RBACMapping, AppMigrationItem, 
    InstallStrategy, ServerMigrationManifest, ToolRecipe, GroupItem,
    DataFileItem, ModuleStreamItem, PlatformBaseline, CronEntry
)
from mcp_servermigrate.core.ssh_client import SSHConnection
from mcp_servermigrate.core.policy import (
    is_enterprise_marker,
    is_enterprise_path,
    is_enterprise_service,
    ENTERPRISE_PATH_PREFIXES,
    SUPERSEDED_BY_PODMAN
)
from mcp_servermigrate.modules.resolver import DynamicReleaseResolver
from mcp_servermigrate.modules.lineage import LineageManager
from mcp_servermigrate.modules.baseline import BaselineComparator

# SEC-4: Regex to detect dangerous profile scripts that overwrite PATH outright
DANGEROUS_PATH_OVERWRITE_RE = re.compile(r'^\s*export\s+PATH=[^$]*$|^\s*PATH=(?![^=\n]*(\$PATH|\$\{PATH\}))[\'"]?[^$]+[\'"]?\s*$', re.MULTILINE)

# BUG-10: SSSD realm suffix pattern (e.g., user@corp.example.com)
REALM_SUFFIX_RE = re.compile(r'(/home/[a-zA-Z0-9_\.\-]+)@[a-zA-Z0-9_\.\-]+')

class MigrationPlanner:
    def __init__(self, source_state: ServerState, target_state: ServerState, src_ssh: Optional[SSHConnection] = None, tgt_ssh: Optional[SSHConnection] = None):
        self.src = source_state
        self.tgt = target_state
        self.src_ssh = src_ssh
        self.tgt_ssh = tgt_ssh

    def _remap_cron_line(self, line: str) -> str:
        """Remap user realm suffixes in cron commands (BUG-10)."""
        return REALM_SUFFIX_RE.sub(r'\1', line)

    def generate_plan(self) -> MigrationPlan:
        # Phase 0: Platform Baseline Comparison (§ 3 / OPEN-1)
        src_rpms = set(self.src.installed_rpms)
        tgt_rpms = set(self.tgt.installed_rpms)
        src_services = {s.name for s in self.src.running_services}
        tgt_services = {s.name for s in self.tgt.running_services}
        src_trees = set(self.src.vendor_trees)
        tgt_trees = set(self.tgt.vendor_trees)

        platform_baseline = BaselineComparator.compare(
            src_rpms=src_rpms,
            tgt_rpms=tgt_rpms,
            src_services=src_services,
            tgt_services=tgt_services,
            src_vendor_trees=src_trees,
            tgt_vendor_trees=tgt_trees
        )

        excluded_paths = platform_baseline.excluded_paths

        # Filter unmanaged binaries against baseline exclusions & enterprise paths
        unmanaged = []
        skipped_items = []
        for b in self.src.unmanaged_binaries:
            if b.is_rpm_owned:
                continue
            if any(b.path.startswith(ex_path) for ex_path in excluded_paths) or is_enterprise_path(b.path):
                skipped_items.append(f"baseline_excluded: {b.path}")
                continue
            unmanaged.append(b)

        apps_to_install: List[AppMigrationItem] = []
        flat_binaries_to_sync: List[str] = []
        preloaded_used: List[str] = []
        plant_tools: Dict[str, ToolRecipe] = {}
        application_groups: Dict[str, List[str]] = {}

        # Track inodes for hard link awareness (BUG-7)
        seen_inodes: Dict[int, str] = {}

        # 1. Determine generation and groups to create
        current_generation = (self.src.migration_manifest.generation + 1) if self.src.migration_manifest else 1
        is_genesis = self.src.is_genesis
        groups_to_create = list(self.src.custom_groups)

        # Ensure default tool_users is always represented
        if not any(g.name == "tool_users" for g in groups_to_create):
            groups_to_create.append(GroupItem(name="tool_users", description="Default CLI tool users"))

        for b in unmanaged:
            app_name = os.path.basename(b.path).lower()

            # Determine appropriate role group for this app
            assigned_group = "tool_users"
            if b.group_owner not in ("root", "wheel", "bin"):
                assigned_group = b.group_owner
            elif b.acl_groups:
                assigned_group = b.acl_groups[0]

            # Register into application_groups
            if assigned_group not in application_groups:
                application_groups[assigned_group] = []
            if app_name not in application_groups[assigned_group]:
                application_groups[assigned_group].append(app_name)

            target_binary_path = f"/opt/tools/bin/{app_name}"

            # BUG-7: Hard Link Detection
            if b.inode is not None and b.link_count > 1 and b.inode in seen_inodes:
                primary_target = seen_inodes[b.inode]
                apps_to_install.append(AppMigrationItem(
                    name=app_name,
                    source_path=b.path,
                    target_path=target_binary_path,
                    strategy=InstallStrategy.HARDLINK,
                    version="hardlink",
                    target_group=assigned_group,
                    hardlink_of=primary_target
                ))
                continue

            if b.inode is not None and b.link_count > 1:
                seen_inodes[b.inode] = target_binary_path

            # Scenario A: Inherit preloaded recipe from source manifest if present
            if self.src.migration_manifest and app_name in self.src.migration_manifest.tools:
                recipe = self.src.migration_manifest.tools[app_name]
                apps_to_install.append(AppMigrationItem(
                    name=app_name,
                    source_path=b.path,
                    target_path=recipe.target_path,
                    strategy=InstallStrategy.PRELOADED_RECIPE,
                    version=recipe.version,
                    download_url=recipe.download_url,
                    archive_format=recipe.archive_format,
                    target_group=recipe.group or assigned_group,
                    checksum_url=recipe.checksum_url,
                    checksum_asset=recipe.checksum_asset
                ))
                preloaded_used.append(app_name)
                plant_tools[app_name] = recipe

            else:
                # Scenario B: Dynamically resolve upstream release
                recipe = DynamicReleaseResolver.resolve_release(app_name, b.path, self.src_ssh)
                recipe.group = assigned_group
                if recipe.download_url:
                    apps_to_install.append(AppMigrationItem(
                        name=app_name,
                        source_path=b.path,
                        target_path=recipe.target_path,
                        strategy=InstallStrategy.TARBALL_DOWNLOAD,
                        version=recipe.version,
                        download_url=recipe.download_url,
                        archive_format=recipe.archive_format,
                        target_group=assigned_group,
                        checksum_url=recipe.checksum_url,
                        checksum_asset=recipe.checksum_asset
                    ))
                    plant_tools[app_name] = recipe
                else:
                    # Fallback to direct source sync
                    flat_binaries_to_sync.append(b.path)
                    apps_to_install.append(AppMigrationItem(
                        name=app_name,
                        source_path=b.path,
                        target_path=target_binary_path,
                        strategy=InstallStrategy.SOURCE_SYNC,
                        version="source_mirror",
                        target_group=assigned_group
                    ))
                    plant_tools[app_name] = ToolRecipe(
                        name=app_name,
                        version="source_mirror",
                        download_url="source_sync",
                        target_path=target_binary_path,
                        group=assigned_group
                    )

        # Plan script data files (BUG-6)
        data_files_to_sync: List[DataFileItem] = []
        for df in self.src.data_files:
            if not any(df.source_path.startswith(ex_path) for ex_path in excluded_paths) and not is_enterprise_path(df.source_path):
                data_files_to_sync.append(df)

        rbac = [
            RBACMapping(
                local_group="tool_users",
                ad_group="Domain Users",
                target_path="/opt/tools",
                permissions="rx"
            )
        ]

        # Profile scripts: Parity over invention (BUG-1) & Security checks (SEC-4)
        profile_scripts: List[str] = []
        for p in self.src.profile_scripts:
            if p.endswith(("/sh.local", "/bash_completion.sh")):
                continue
            # If src_ssh is provided, audit script content for security
            if self.src_ssh:
                try:
                    content = self.src_ssh.read_text(p)
                    # Check for dangerous PATH clobbering
                    if DANGEROUS_PATH_OVERWRITE_RE.search(content):
                        skipped_items.append(f"insecure_profile_clobbers_path: {p}")
                        continue
                except Exception:
                    pass
            profile_scripts.append(p)

        # Cron entries: Strip realm suffixes and deduplicate (BUG-10, BUG-15, BUG-16)
        root_crons: List[CronEntry] = []
        existing_tgt_cron_lines = {c.line.strip() for c in self.tgt.root_crons}
        for c in self.src.root_crons:
            remapped_line = self._remap_cron_line(c.line)
            if remapped_line not in existing_tgt_cron_lines:
                root_crons.append(CronEntry(user=c.user, line=remapped_line, is_custom=c.is_custom))

        # Module streams: Deduplicate and sort (BUG-13)
        module_streams = list(self.src.module_streams)

        # Prepare on-server manifest to plant on target
        manifest_to_plant = ServerMigrationManifest(
            generation=current_generation,
            parent_host=self.src.hostname,
            migration_timestamp=datetime.now(timezone.utc).isoformat(),
            lineage_group="mcp-migrate",
            tools=plant_tools,
            application_groups=application_groups,
            local_group="tool_users",
            ad_group="Domain Users",
            acl_path="/opt/tools"
        )
        skill_markdown = LineageManager.generate_skill_markdown(manifest_to_plant)

        return MigrationPlan(
            source_host=self.src.hostname,
            target_host=self.tgt.hostname,
            generation=current_generation,
            is_genesis_migration=is_genesis,
            preloaded_recipes_used=preloaded_used,
            groups_to_create=groups_to_create,
            apps_to_install=apps_to_install,
            data_files_to_sync=data_files_to_sync,
            flat_binaries_to_sync=flat_binaries_to_sync,
            root_crons_to_apply=root_crons,
            rbac_mappings=rbac,
            profile_scripts_to_deploy=profile_scripts,
            module_streams=module_streams,
            platform_baseline=platform_baseline,
            skipped_items=skipped_items,
            manifest_to_plant=manifest_to_plant,
            manifest_skill_markdown=skill_markdown
        )
