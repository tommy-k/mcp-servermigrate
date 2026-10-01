import os
import stat
import tempfile
import pytest
from unittest.mock import MagicMock
from mcp_servermigrate.core.models import (
    ServerState, BinaryItem, DataFileItem, CronEntry, ServiceItem, GroupItem,
    InstallStrategy
)
from mcp_servermigrate.core.security import EphemeralCredentialVault
from mcp_servermigrate.modules.baseline import BaselineComparator
from mcp_servermigrate.modules.planner import MigrationPlanner
from mcp_servermigrate.modules.executor import MigrationExecutor

def test_phase_0_baseline_comparator_excludes_enterprise_and_target_only():
    src_trees = {"/opt/dynatrace", "/opt/tools/myapp"}
    tgt_trees = {"/opt/dynatrace", "/opt/splunkforwarder"}

    src_rpms = {"falcon-sensor", "custom-app-1.0"}
    tgt_rpms = {"falcon-sensor", "target-only-rpm"}

    baseline = BaselineComparator.compare(
        src_rpms=src_rpms,
        tgt_rpms=tgt_rpms,
        src_services={"dynatrace.service"},
        tgt_services={"dynatrace.service", "splunk.service"},
        src_vendor_trees=src_trees,
        tgt_vendor_trees=tgt_trees
    )

    # Dynatrace on both -> BASELINE
    dt_entry = next(e for e in baseline.entries if e.name == "/opt/dynatrace")
    assert dt_entry.classification == "BASELINE"
    assert "/opt/dynatrace" in baseline.excluded_paths

    # Splunk on target only -> TARGET_ONLY
    sp_entry = next(e for e in baseline.entries if e.name == "/opt/splunkforwarder")
    assert sp_entry.classification == "TARGET_ONLY"
    assert "/opt/splunkforwarder" in baseline.excluded_paths

    # Custom app on src only -> CANDIDATE
    app_entry = next(e for e in baseline.entries if e.name == "/opt/tools/myapp")
    assert app_entry.classification == "CANDIDATE"
    assert "/opt/tools/myapp" not in baseline.excluded_paths

    # falcon-sensor on both -> BASELINE
    falcon_entry = next(e for e in baseline.entries if e.name == "falcon-sensor")
    assert falcon_entry.classification == "BASELINE"
    assert "falcon-sensor" in baseline.excluded_packages

def test_enterprise_missing_on_target_never_copied():
    # Falcon / Dynatrace on source, missing on target
    src_trees = {"/opt/dynatrace"}
    tgt_trees = set()

    src_rpms = {"falcon-sensor"}
    tgt_rpms = set()

    baseline = BaselineComparator.compare(
        src_rpms=src_rpms,
        tgt_rpms=tgt_rpms,
        src_services={"dynatrace.service"},
        tgt_services=set(),
        src_vendor_trees=src_trees,
        tgt_vendor_trees=tgt_trees
    )

    dt_entry = next(e for e in baseline.entries if e.name == "/opt/dynatrace")
    assert dt_entry.classification == "BASELINE_MISSING_ON_TARGET"
    assert "/opt/dynatrace" in baseline.excluded_paths

    falcon_entry = next(e for e in baseline.entries if e.name == "falcon-sensor")
    assert falcon_entry.classification == "BASELINE_MISSING_ON_TARGET"
    assert "falcon-sensor" in baseline.excluded_packages

def test_sec_2_sudo_pass_file_permissions():
    vault = EphemeralCredentialVault.get_vault()

    with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
        f.write("super_secret_password\n")
        temp_path = f.name

    try:
        # 1. Insecure mode (0644) should fail on POSIX
        os.chmod(temp_path, 0o644)
        with pytest.raises(PermissionError, match="Insecure permissions"):
            vault.load_sudo_pass_file(temp_path)

        # 2. Secure mode (0600) should succeed
        os.chmod(temp_path, 0o600)
        vault.load_sudo_pass_file(temp_path, host="test-host")
        assert vault.get_sudo_password("test-host") == "super_secret_password"
    finally:
        os.unlink(temp_path)

def test_sec_4_profile_script_path_overwrites_rejected():
    mock_ssh = MagicMock()
    # Script A clobbers PATH outright
    # Script B cleanly appends to PATH
    def mock_read(path):
        if "bad_env.sh" in path:
            return "export PATH=/custom/bin\n"
        return "export PATH=$PATH:/custom/bin\n"
    mock_ssh.read_text.side_effect = mock_read

    src = ServerState(
        hostname="src.corp",
        os_release="RHEL 8",
        profile_scripts=["/etc/profile.d/bad_env.sh", "/etc/profile.d/good_env.sh"]
    )
    tgt = ServerState(hostname="tgt.corp", os_release="RHEL 9")

    planner = MigrationPlanner(src, tgt, src_ssh=mock_ssh)
    plan = planner.generate_plan()

    assert "/etc/profile.d/good_env.sh" in plan.profile_scripts_to_deploy
    assert "/etc/profile.d/bad_env.sh" not in plan.profile_scripts_to_deploy
    assert any("bad_env.sh" in s for s in plan.skipped_items)

def test_bug_7_hardlink_planning():
    # Two binaries sharing the same inode (e.g. kubectl and oc)
    src = ServerState(
        hostname="src.corp",
        os_release="RHEL 8",
        unmanaged_binaries=[
            BinaryItem(
                path="/usr/local/bin/kubectl",
                is_rpm_owned=False,
                group_owner="devs",
                inode=123456,
                link_count=2,
                is_executable=True
            ),
            BinaryItem(
                path="/usr/local/bin/oc",
                is_rpm_owned=False,
                group_owner="devs",
                inode=123456,
                link_count=2,
                is_executable=True
            )
        ]
    )
    tgt = ServerState(hostname="tgt.corp", os_release="RHEL 9")
    planner = MigrationPlanner(src, tgt)
    plan = planner.generate_plan()

    assert len(plan.apps_to_install) == 2
    primary = next(a for a in plan.apps_to_install if a.name == "kubectl")
    secondary = next(a for a in plan.apps_to_install if a.name == "oc")

    assert secondary.strategy == InstallStrategy.HARDLINK
    assert secondary.hardlink_of == "/opt/tools/bin/kubectl"

def test_bug_6_data_files_planning():
    src = ServerState(
        hostname="src.corp",
        os_release="RHEL 8",
        data_files=[
            DataFileItem(
                source_path="/opt/scripts/servers.txt",
                target_path="/opt/scripts/servers.txt",
                mode="0644",
                owner="root",
                group="root"
            )
        ]
    )
    tgt = ServerState(hostname="tgt.corp", os_release="RHEL 9")
    planner = MigrationPlanner(src, tgt)
    plan = planner.generate_plan()

    assert len(plan.data_files_to_sync) == 1
    assert plan.data_files_to_sync[0].source_path == "/opt/scripts/servers.txt"

def test_bug_10_cron_realm_remapping_and_dedup():
    src = ServerState(
        hostname="src.corp",
        os_release="RHEL 8",
        root_crons=[
            CronEntry(user="root", line="0 2 * * * /home/admin@CORP.INTERNAL/backup.sh"),
            CronEntry(user="root", line="0 3 * * * /usr/bin/existing_job.sh")
        ]
    )
    tgt = ServerState(
        hostname="tgt.corp",
        os_release="RHEL 9",
        root_crons=[
            CronEntry(user="root", line="0 3 * * * /usr/bin/existing_job.sh")
        ]
    )
    planner = MigrationPlanner(src, tgt)
    plan = planner.generate_plan()

    # The existing job on target should be deduplicated
    assert len(plan.root_crons_to_apply) == 1
    # Realm suffix should be remapped
    assert plan.root_crons_to_apply[0].line == "0 2 * * * /home/admin/backup.sh"

def test_bug_2_stage_approval_filtering():
    src_mock = MagicMock()
    tgt_mock = MagicMock()

    src = ServerState(
        hostname="src.corp",
        os_release="RHEL 8",
        custom_groups=[GroupItem(name="mygroup", gid=1005)],
        root_crons=[CronEntry(user="root", line="* * * * * /bin/true")]
    )
    tgt = ServerState(hostname="tgt.corp", os_release="RHEL 9")
    planner = MigrationPlanner(src, tgt)
    plan = planner.generate_plan()

    # Run executor with ONLY stage 'groups' approved
    executor = MigrationExecutor(plan, src_mock, tgt_mock, approved_stages={"groups"})
    executor.execute_plan()

    # Target should receive group creation command
    assert any("groupadd" in str(call) for call in tgt_mock.run_privileged.mock_calls)
    # Target should NOT receive crontab command
    assert not any("crontab" in str(call) for call in tgt_mock.run_privileged.mock_calls)
