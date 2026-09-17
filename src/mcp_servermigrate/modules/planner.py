import os
from datetime import datetime, timezone
from mcp_servermigrate.core.models import (
    ServerState, MigrationPlan, RBACMapping, AppMigrationItem, 
    InstallStrategy, ServerMigrationManifest, ToolRecipe, GroupItem
)
from mcp_servermigrate.core.ssh_client import SSHConnection
from mcp_servermigrate.modules.resolver import DynamicReleaseResolver
from mcp_servermigrate.modules.lineage import LineageManager

class MigrationPlanner:
    def __init__(self, source_state: ServerState, target_state: ServerState, src_ssh: SSHConnection = None, tgt_ssh: SSHConnection = None):
        self.src = source_state
        self.tgt = target_state
        self.src_ssh = src_ssh
        self.tgt_ssh = tgt_ssh

    def generate_plan(self) -> MigrationPlan:
        unmanaged = [b for b in self.src.unmanaged_binaries if not b.is_rpm_owned]
        apps_to_install: list[AppMigrationItem] = []
        flat_binaries_to_sync: list[str] = []
        preloaded_used: list[str] = []
        plant_tools: dict[str, ToolRecipe] = {}
        application_groups: dict[str, list[str]] = {}

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
                    target_group=recipe.group or assigned_group
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
                        target_group=assigned_group
                    ))
                    plant_tools[app_name] = recipe
                else:
                    # Fallback to direct source rsync
                    flat_binaries_to_sync.append(b.path)
                    apps_to_install.append(AppMigrationItem(
                        name=app_name,
                        source_path=b.path,
                        target_path=f"/opt/tools/bin/{app_name}",
                        strategy=InstallStrategy.SOURCE_SYNC,
                        version="source_mirror",
                        target_group=assigned_group
                    ))
                    plant_tools[app_name] = ToolRecipe(
                        name=app_name,
                        version="source_mirror",
                        download_url="source_sync",
                        target_path=f"/opt/tools/bin/{app_name}",
                        group=assigned_group
                    )

        rbac = [
            RBACMapping(
                local_group="tool_users",
                ad_group="Domain Users",
                target_path="/opt/tools",
                permissions="rx"
            )
        ]

        profile_scripts = [
            p for p in self.src.profile_scripts if not p.endswith(("/sh.local", "/bash_completion.sh"))
        ]

        # Prepare on-server manifest to plant on target (Includes Application Groups Matrix)
        manifest_to_plant = ServerMigrationManifest(
            generation=current_generation,
            parent_host=self.src.hostname,
            migration_timestamp=datetime.now(timezone.utc).isoformat(),
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
            flat_binaries_to_sync=flat_binaries_to_sync,
            root_crons_to_apply=self.src.root_crons,
            rbac_mappings=rbac,
            profile_scripts_to_deploy=profile_scripts,
            manifest_to_plant=manifest_to_plant,
            manifest_skill_markdown=skill_markdown
        )
