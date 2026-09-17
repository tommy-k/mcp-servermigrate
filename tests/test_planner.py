from mcp_servermigrate.core.models import (
    ServerState, BinaryItem, ServerMigrationManifest, ToolRecipe, InstallStrategy, GroupItem
)
from mcp_servermigrate.modules.planner import MigrationPlanner
from mcp_servermigrate.modules.resolver import DynamicReleaseResolver

def test_genesis_planner_captures_custom_groups_and_apps():
    # Server 1: Genesis host with custom application groups
    src = ServerState(
        hostname="server-01.corp",
        os_release="Red Hat Enterprise Linux 9.4 (Plow)",
        is_genesis=True,
        custom_groups=[
            GroupItem(name="terraform_users", gid=1001, associated_apps=["terraform"]),
            GroupItem(name="git_users", gid=1002, associated_apps=["gh"])
        ],
        unmanaged_binaries=[
            BinaryItem(path="/usr/local/bin/terraform", is_rpm_owned=False, group_owner="terraform_users"),
            BinaryItem(path="/usr/local/bin/gh", is_rpm_owned=False, group_owner="git_users")
        ]
    )
    tgt = ServerState(hostname="server-02.corp", os_release="Rocky Linux 9.4 (Blue Onyx)")
    planner = MigrationPlanner(src, tgt)
    plan = planner.generate_plan()

    assert plan.is_genesis_migration is True
    assert plan.generation == 1
    assert len(plan.apps_to_install) == 2

    # Verify custom groups are captured for creation on Target Server
    group_names = [g.name for g in plan.groups_to_create]
    assert "terraform_users" in group_names
    assert "git_users" in group_names
    assert "tool_users" in group_names

    # Verify applications are mapped to their specific custom groups
    tf_app = next(a for a in plan.apps_to_install if a.name == "terraform")
    assert tf_app.target_group == "terraform_users"
    gh_app = next(a for a in plan.apps_to_install if a.name == "gh")
    assert gh_app.target_group == "git_users"

    # Verify manifest application_groups contract is built
    assert plan.manifest_to_plant is not None
    assert "terraform_users" in plan.manifest_to_plant.application_groups
    assert "terraform" in plan.manifest_to_plant.application_groups["terraform_users"]
    assert "git_users" in plan.manifest_to_plant.application_groups
    assert "gh" in plan.manifest_to_plant.application_groups["git_users"]

def test_generational_planner_preloads_inherited_recipes():
    # Server 2: Generational host (has /etc/mcp-migration lineage from Server 1)
    manifest = ServerMigrationManifest(
        generation=1,
        parent_host="server-01.corp",
        migration_timestamp="2026-09-16T23:00:00Z",
        tools={
            "terraform": ToolRecipe(
                name="terraform",
                version="1.9.5",
                download_url="https://releases.hashicorp.com/terraform/1.9.5/terraform_1.9.5_linux_amd64.zip",
                target_path="/opt/tools/bin/terraform",
                group="terraform_users",
                archive_format="zip"
            )
        },
        application_groups={
            "terraform_users": ["terraform"]
        }
    )
    src = ServerState(
        hostname="server-02.corp",
        os_release="AlmaLinux 9.4 (Seafoam Ocelot)",
        is_genesis=False,
        migration_manifest=manifest,
        custom_groups=[GroupItem(name="terraform_users", gid=1001)],
        unmanaged_binaries=[
            BinaryItem(path="/opt/tools/bin/terraform", is_rpm_owned=False, group_owner="terraform_users")
        ]
    )
    tgt = ServerState(hostname="server-03.corp", os_release="Enterprise Linux 9")
    planner = MigrationPlanner(src, tgt)
    plan = planner.generate_plan()

    assert plan.is_genesis_migration is False
    assert plan.generation == 2
    assert "terraform" in plan.preloaded_recipes_used
    tf_app = next(a for a in plan.apps_to_install if a.name == "terraform")
    assert tf_app.strategy == InstallStrategy.PRELOADED_RECIPE
    assert tf_app.target_group == "terraform_users"
    assert plan.manifest_to_plant.generation == 2
    assert plan.manifest_to_plant.parent_host == "server-02.corp"
