import os
from datetime import datetime, timezone
from mcp_servermigrate.core.models import (
    ServerState, MigrationPlan, RBACMapping, AppMigrationItem, 
    InstallStrategy, ServerMigrationManifest, ToolRecipe
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

        # Determine generation
        current_generation = (self.src.migration_manifest.generation + 1) if self.src.migration_manifest else 1
        is_genesis = self.src.is_genesis

        for b in unmanaged:
            app_name = os.path.basename(b.path).lower()

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
                    target_group=recipe.group
                ))
                preloaded_used.append(app_name)
                plant_tools[app_name] = recipe

            else:
                # Scenario B: Dynamically resolve upstream release
                recipe = DynamicReleaseResolver.resolve_release(app_name, b.path, self.src_ssh)
                if recipe.download_url:
                    apps_to_install.append(AppMigrationItem(
                        name=app_name,
                        source_path=b.path,
                        target_path=recipe.target_path,
                        strategy=InstallStrategy.TARBALL_DOWNLOAD,
                        version=recipe.version,
                        download_url=recipe.download_url,
                        archive_format=recipe.archive_format,
                        target_group=recipe.group
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
                        target_group="tool_users"
                    ))
                    plant_tools[app_name] = ToolRecipe(
                        name=app_name,
                        version="source_mirror",
                        download_url="source_sync",
                        target_path=f"/opt/tools/bin/{app_name}",
                        group="tool_users"
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

        # Prepare on-server manifest to plant on target
        manifest_to_plant = ServerMigrationManifest(
            generation=current_generation,
            parent_host=self.src.hostname,
            migration_timestamp=datetime.now(timezone.utc).isoformat(),
            tools=plant_tools,
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
            apps_to_install=apps_to_install,
            flat_binaries_to_sync=flat_binaries_to_sync,
            root_crons_to_apply=self.src.root_crons,
            rbac_mappings=rbac,
            profile_scripts_to_deploy=profile_scripts,
            manifest_to_plant=manifest_to_plant,
            manifest_skill_markdown=skill_markdown
        )
