import json
from unittest.mock import MagicMock
from mcp_servermigrate.modules.collector import RemoteCollector
from mcp_servermigrate.modules.discovery import DiscoveryEngine
from mcp_servermigrate.core.models import ServerState

def test_remote_collector_command_format():
    cmd = RemoteCollector.get_collector_command()
    assert cmd.startswith("python3 -c 'import base64; exec(base64.b64decode(")
    assert "2>/dev/null" in cmd

def test_discovery_engine_fast_path():
    mock_ssh = MagicMock()
    mock_ssh.host = "test-host.corp"

    sample_payload = {
        "hostname": "test-host.corp",
        "os_release": "Red Hat Enterprise Linux 9.4",
        "is_genesis": True,
        "migration_manifest": None,
        "custom_groups": [
            {"name": "ops_users", "gid": 1005, "members": ["alice"], "associated_apps": ["terraform"]}
        ],
        "unmanaged_binaries": [
            {
                "path": "/usr/local/bin/terraform",
                "is_rpm_owned": False,
                "package_name": None,
                "group_owner": "ops_users",
                "acl_groups": [],
                "permissions": "755",
                "inode": 45678,
                "link_count": 1,
                "is_executable": True,
                "mode": "755"
            }
        ],
        "data_files": [],
        "module_streams": [],
        "vendor_trees": ["/opt/tools"],
        "installed_rpms": ["bash", "systemd", "kernel"],
        "root_crons": [],
        "running_services": [],
        "profile_scripts": ["/etc/profile.d/lang.sh"]
    }

    # Simulate 1-Shot Remote Collector returning JSON on first call
    mock_ssh.run_cmd.return_value = json.dumps(sample_payload)

    engine = DiscoveryEngine(mock_ssh)
    state = engine.discover_state()

    assert state.hostname == "test-host.corp"
    assert len(state.custom_groups) == 1
    assert state.custom_groups[0].name == "ops_users"
    assert len(state.unmanaged_binaries) == 1
    assert state.unmanaged_binaries[0].path == "/usr/local/bin/terraform"

    # Verify that only 1 single SSH call was made! (No chatty round-trips)
    assert mock_ssh.run_cmd.call_count == 1
