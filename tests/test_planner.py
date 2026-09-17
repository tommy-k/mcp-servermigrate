from mcp_servermigrate.core.models import (
    ServerState, BinaryItem, ServerMigrationManifest, ToolRecipe, InstallStrategy
)
from mcp_servermigrate.modules.planner import MigrationPlanner

def test_genesis_planner_resolves_upstream_tarball():
    # Server 1: Genesis host (no prior manifest)
    src = ServerState(
        hostname="server-01.corp",
        os_release="Fedora 44",
        is_genesis=True,
        unmanaged_binaries=[
            BinaryItem(path="/usr/local/bin/terraform", is_rpm_owned=False),
            BinaryItem(path="/usr/local/bin/gh", is_rpm_owned=False)
        ]
    )
    tgt = ServerState(hostname="server-02.corp", os_release="Fedora 44")
    planner = MigrationPlanner(src, tgt)
    plan = planner.generate_plan()

    assert plan.is_genesis_migration is True
    assert plan.generation == 1
    assert len(plan.apps_to_install) == 2
    tf_app = next(a for a in plan.apps_to_install if a.name == "terraform")
    assert tf_app.strategy == InstallStrategy.TARBALL_DOWNLOAD
    assert "hashicorp.com" in tf_app.download_url
    assert plan.manifest_to_plant is not None
    assert plan.manifest_to_plant.generation == 1

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
                group="tool_users",
                archive_format="zip"
            )
        }
    )
    src = ServerState(
        hostname="server-02.corp",
        os_release="Fedora 44",
        is_genesis=False,
        migration_manifest=manifest,
        unmanaged_binaries=[
            BinaryItem(path="/opt/tools/bin/terraform", is_rpm_owned=False)
        ]
    )
    tgt = ServerState(hostname="server-03.corp", os_release="Fedora 44")
    planner = MigrationPlanner(src, tgt)
    plan = planner.generate_plan()

    assert plan.is_genesis_migration is False
    assert plan.generation == 2
    assert "terraform" in plan.preloaded_recipes_used
    tf_app = next(a for a in plan.apps_to_install if a.name == "terraform")
    assert tf_app.strategy == InstallStrategy.PRELOADED_RECIPE
    assert tf_app.download_url == "https://releases.hashicorp.com/terraform/1.9.5/terraform_1.9.5_linux_amd64.zip"
    assert plan.manifest_to_plant.generation == 2
    assert plan.manifest_to_plant.parent_host == "server-02.corp"
