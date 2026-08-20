from mcp_servermigrate.core.models import ServerState, BinaryItem
from mcp_servermigrate.modules.planner import MigrationPlanner

def test_planner_detects_unmanaged_binaries():
    src = ServerState(
        hostname="source.corp",
        os_release="Fedora 44",
        unmanaged_binaries=[
            BinaryItem(path="/opt/tools/bin/gh", is_rpm_owned=False),
            BinaryItem(path="/usr/bin/git", is_rpm_owned=True, package_name="git-2.43.0")
        ]
    )
    tgt = ServerState(hostname="target.corp", os_release="Fedora 44")
    planner = MigrationPlanner(src, tgt)
    plan = planner.generate_plan()

    assert "/opt/tools/bin/gh" in plan.flat_binaries_to_sync
    assert "/usr/bin/git" not in plan.flat_binaries_to_sync
