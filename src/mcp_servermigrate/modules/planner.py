import os
import re
from datetime import datetime, timezone
from typing import List, Dict, Optional, Set
from concurrent.futures import ThreadPoolExecutor
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
DANGEROUS_PATH_OVERWRITE_RE = re.compile(
    r'^\s*export\s+PATH=[^$]*$|^\s*PATH=(?![^=\n]*(\$PATH|\$\{PATH\}))[\'"]?[^$]+[\'"]?\s*$',
    re.MULTILINE
)

# BUG-10: SSSD realm suffix pattern (e.g., user@corp.example.com)
REALM_SUFFIX_RE = re.compile(r'(/home/[a-zA-Z0-9_\.\-]+)@[a-zA-Z0-9_\.\-]+')

# Extract file paths referenced in cron lines (scripts, configs, data files)
CRON_PATH_RE = re.compile(r'(/(?:opt|usr/local|etc|home|var/opt)/[a-zA-Z0-9_.\-/@]+)')


class MigrationPlanner:
    def __init__(
        self,
        source_state: ServerState,
        target_state: ServerState,
        src_ssh: Optional[SSHConnection] = None,
        tgt_ssh: Optional[SSHConnection] = None,
        known_recipes: Optional[Dict[str, ToolRecipe]] = None,
        declined_profile_scripts: Optional[Set[str]] = None,
    ):
        self.src = source_state
        self.tgt = target_state
        self.src_ssh = src_ssh
        self.tgt_ssh = tgt_ssh
        self.known_recipes = known_recipes or {}
        self.declined_profile_scripts = declined_profile_scripts or set()

    def _remap_cron_line(self, line: str) -> str:
        """Remap user realm suffixes in cron commands (BUG-10)."""
        return REALM_SUFFIX_RE.sub(r'\1', line)

    def _extract_cron_dependencies(
        self,
        cron_line: str,
        existing_sources: Set[str],
        excluded_paths: Set[str],
    ) -> List[DataFileItem]:
        """Extract referenced script/data file dependencies from a cron job line."""
        deps: List[DataFileItem] = []
        for match in CRON_PATH_RE.findall(cron_line):
            clean_src = match.rstrip(".,;:'\"")
            if clean_src in existing_sources:
                continue
            if any(clean_src.startswith(ex) for ex in excluded_paths) or is_enterprise_path(clean_src):
                continue

            remapped_target = REALM_SUFFIX_RE.sub(r'\1', clean_src)
            owner = "root"
            home_match = re.match(r'^/home/([a-zA-Z0-9_.\-]+)(?:@[^/]+)?/', clean_src)
            if home_match:
                owner = home_match.group(1)

            existing_sources.add(clean_src)
            deps.append(DataFileItem(
                source_path=clean_src,
                target_path=remapped_target,
                mode="0750" if clean_src.endswith(".sh") else "0644",
                owner=owner,
                group="root" if owner == "root" else owner,
            ))
        return deps

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

        # Collect candidate packages for real `packages` stage (`dnf install` first)
        packages_to_install = [
            entry.name
            for entry in platform_baseline.entries
            if entry.kind == "rpm"
            and entry.classification == "CANDIDATE"
            and entry.name not in SUPERSEDED_BY_PODMAN
        ]

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
        symlinks_to_create: Dict[str, str] = {}
        flat_binaries_to_sync: List[str] = []
        preloaded_used: List[str] = []
        plant_tools: Dict[str, ToolRecipe] = {}
        application_groups: Dict[str, List[str]] = {"tool_users": []}

        # Track inodes for hard link awareness (BUG-7)
        seen_inodes: Dict[int, str] = {}
        apps_to_probe_breadcrumbs = []

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

            # Every published CLI tool MUST be listed in tool_users so onboarding matches ACLs
            if app_name not in application_groups["tool_users"]:
                application_groups["tool_users"].append(app_name)
            if assigned_group != "tool_users":
                application_groups.setdefault(assigned_group, [])
                if app_name not in application_groups[assigned_group]:
                    application_groups[assigned_group].append(app_name)

            target_binary_path = f"/opt/tools/bin/{app_name}"
            # Publish symlink in /usr/local/bin/<tool> -> /opt/tools/bin/<tool>
            symlinks_to_create[f"/usr/local/bin/{app_name}"] = target_binary_path

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

            # Scenario A: Explicit known recipe (from inherited manifest or known_recipes registry)
            if self.src.migration_manifest and app_name in self.src.migration_manifest.tools:
                recipe = self.src.migration_manifest.tools[app_name]
                use_download = bool(recipe.download_url and recipe.download_url != "source_sync")
                apps_to_install.append(AppMigrationItem(
                    name=app_name,
                    source_path=b.path,
                    target_path=recipe.target_path or target_binary_path,
                    strategy=InstallStrategy.PRELOADED_RECIPE if use_download else InstallStrategy.SOURCE_SYNC,
                    version=recipe.version,
                    download_url=recipe.download_url if use_download else None,
                    archive_format=recipe.archive_format,
                    target_group=recipe.group or assigned_group,
                    checksum_url=recipe.checksum_url,
                    checksum_asset=recipe.checksum_asset
                ))
                if not use_download:
                    flat_binaries_to_sync.append(b.path)
                preloaded_used.append(app_name)
                plant_tools[app_name] = recipe
            elif app_name in self.known_recipes:
                recipe = self.known_recipes[app_name]
                use_download = bool(recipe.download_url and recipe.download_url != "source_sync")
                apps_to_install.append(AppMigrationItem(
                    name=app_name,
                    source_path=b.path,
                    target_path=recipe.target_path or target_binary_path,
                    strategy=InstallStrategy.TARBALL_DOWNLOAD if use_download else InstallStrategy.SOURCE_SYNC,
                    version=recipe.version,
                    download_url=recipe.download_url if use_download else None,
                    archive_format=recipe.archive_format,
                    target_group=assigned_group,
                    checksum_url=recipe.checksum_url,
                    checksum_asset=recipe.checksum_asset
                ))
                if not use_download:
                    flat_binaries_to_sync.append(b.path)
                plant_tools[app_name] = recipe
            else:
                # Default: Copy source binaries byte-for-byte; probe recipe breadcrumbs for future migrations
                flat_binaries_to_sync.append(b.path)
                apps_to_install.append(AppMigrationItem(
                    name=app_name,
                    source_path=b.path,
                    target_path=target_binary_path,
                    strategy=InstallStrategy.SOURCE_SYNC,
                    version="source_mirror",
                    target_group=assigned_group
                ))
                apps_to_probe_breadcrumbs.append((app_name, b.path, assigned_group, target_binary_path))

        # Probe recipe breadcrumbs concurrently for manifest documentation without switching away from SOURCE_SYNC
        if apps_to_probe_breadcrumbs:
            if self.src_ssh is not None:
                with ThreadPoolExecutor(max_workers=min(len(apps_to_probe_breadcrumbs), 6)) as pool:
                    futures = [
                        (app_name, b_path, assigned_group, target_binary_path,
                         pool.submit(DynamicReleaseResolver.resolve_release, app_name, b_path, self.src_ssh))
                        for app_name, b_path, assigned_group, target_binary_path in apps_to_probe_breadcrumbs
                    ]
                    for app_name, b_path, assigned_group, target_binary_path, fut in futures:
                        recipe = fut.result()
                        recipe.group = assigned_group
                        recipe.target_path = target_binary_path
                        if not recipe.download_url:
                            recipe.download_url = "source_sync"
                        plant_tools[app_name] = recipe
            else:
                for app_name, b_path, assigned_group, target_binary_path in apps_to_probe_breadcrumbs:
                    recipe = DynamicReleaseResolver.resolve_release(app_name, b_path, None)
                    recipe.group = assigned_group
                    recipe.target_path = target_binary_path
                    if not recipe.download_url:
                        recipe.download_url = "source_sync"
                    plant_tools[app_name] = recipe

        # Plan script data files (BUG-6)
        data_files_to_sync: List[DataFileItem] = []
        seen_data_sources: Set[str] = set()
        for df in self.src.data_files:
            if not any(df.source_path.startswith(ex_path) for ex_path in excluded_paths) and not is_enterprise_path(df.source_path):
                data_files_to_sync.append(df)
                seen_data_sources.add(df.source_path)

        rbac = [
            RBACMapping(
                local_group="tool_users",
                ad_group="Domain Users",
                target_path="/opt/tools",
                permissions="rx"
            )
        ]

        # Profile scripts: never overwrite target's stock scripts, skip world-writable & user-declined
        tgt_profile_basenames = {os.path.basename(p) for p in self.tgt.profile_scripts}
        declined_names = {os.path.basename(d) for d in self.declined_profile_scripts} | self.declined_profile_scripts

        profile_scripts: List[str] = []
        for p in self.src.profile_scripts:
            p_base = os.path.basename(p)
            if p.endswith(("/sh.local", "/bash_completion.sh")):
                continue
            if p in tgt_profile_basenames or p_base in tgt_profile_basenames:
                skipped_items.append(f"target_stock_profile_preserved: {p}")
                continue
            if p in declined_names or p_base in declined_names:
                skipped_items.append(f"user_declined_profile: {p}")
                continue
            if self.src_ssh:
                try:
                    mode_out = self.src_ssh.run_cmd(f"stat -c '%a' '{p}' 2>/dev/null")
                    if isinstance(mode_out, str) and mode_out.strip() and (int(mode_out.strip(), 8) & 0o002) != 0:
                        skipped_items.append(f"insecure_world_writable_profile: {p}")
                        continue
                except Exception:
                    pass
                try:
                    content = self.src_ssh.read_text(p)
                    if isinstance(content, str) and DANGEROUS_PATH_OVERWRITE_RE.search(content):
                        skipped_items.append(f"insecure_profile_clobbers_path: {p}")
                        continue
                except Exception:
                    pass
            profile_scripts.append(p)

        # Cron entries: strip realm suffixes, deduplicate, and carry referenced dependencies
        root_crons: List[CronEntry] = []
        existing_tgt_cron_lines = {c.line.strip() for c in self.tgt.root_crons}
        for c in self.src.root_crons:
            remapped_line = self._remap_cron_line(c.line)
            if remapped_line not in existing_tgt_cron_lines:
                root_crons.append(CronEntry(user=c.user, line=remapped_line, is_custom=c.is_custom))
                deps = self._extract_cron_dependencies(c.line, seen_data_sources, excluded_paths)
                data_files_to_sync.extend(deps)

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
            packages_to_install=packages_to_install,
            apps_to_install=apps_to_install,
            symlinks_to_create=symlinks_to_create,
            data_files_to_sync=data_files_to_sync,
            flat_binaries_to_sync=flat_binaries_to_sync,
            root_crons_to_apply=root_crons,
            rbac_mappings=rbac,
            profile_scripts_to_deploy=profile_scripts,
            module_streams=module_streams,
            platform_baseline=platform_baseline,
            informational_pam_rules=list(self.src.informational_pam_rules),
            skipped_items=skipped_items,
            manifest_to_plant=manifest_to_plant,
            manifest_skill_markdown=skill_markdown
        )
