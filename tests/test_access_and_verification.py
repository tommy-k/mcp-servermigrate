import pytest
from unittest.mock import MagicMock
from mcp_servermigrate.core.models import (
    ServerState, BinaryItem, CronEntry, ToolRecipe, InstallStrategy
)
from mcp_servermigrate.modules.planner import MigrationPlanner
from mcp_servermigrate.modules.executor import MigrationExecutor
from mcp_servermigrate.modules.verifier import PostFlightVerifier


def test_default_byte_for_byte_sync_with_breadcrumbs_and_tool_users_symlinks():
    src = ServerState(
        hostname="src.corp",
        os_release="RHEL 8",
        unmanaged_binaries=[
            BinaryItem(path="/usr/local/bin/terraform", is_rpm_owned=False, group_owner="terraform_users"),
            BinaryItem(path="/usr/local/bin/gh", is_rpm_owned=False, group_owner="git_users"),
        ],
        informational_pam_rules=["sshd; *; %Domain Users; Al0000-2400; tool_users"],
    )
    tgt = ServerState(hostname="tgt.corp", os_release="RHEL 9")

    planner = MigrationPlanner(src, tgt)
    plan = planner.generate_plan()

    # Default strategy is SOURCE_SYNC (byte-for-byte copy), NOT downloading from internet
    for app in plan.apps_to_install:
        assert app.strategy == InstallStrategy.SOURCE_SYNC

    # Breadcrumbs still populated in manifest.tools
    assert "terraform" in plan.manifest_to_plant.tools
    assert "releases.hashicorp.com" in (plan.manifest_to_plant.tools["terraform"].download_url or "")

    # application_groups["tool_users"] must list EVERY published CLI tool
    assert "terraform" in plan.manifest_to_plant.application_groups["tool_users"]
    assert "gh" in plan.manifest_to_plant.application_groups["tool_users"]

    # Symlinks in /usr/local/bin -> /opt/tools/bin/*
    assert plan.symlinks_to_create["/usr/local/bin/terraform"] == "/opt/tools/bin/terraform"
    assert plan.symlinks_to_create["/usr/local/bin/gh"] == "/opt/tools/bin/gh"

    # Informational PAM rules reported, never applied
    assert len(plan.informational_pam_rules) == 1


def test_known_recipe_list_allows_tarball_download():
    src = ServerState(
        hostname="src.corp",
        os_release="RHEL 8",
        unmanaged_binaries=[
            BinaryItem(path="/usr/local/bin/jq", is_rpm_owned=False, group_owner="tool_users"),
        ],
    )
    tgt = ServerState(hostname="tgt.corp", os_release="RHEL 9")
    known = {
        "jq": ToolRecipe(
            name="jq",
            version="1.7.1",
            download_url="https://example.com/jq",
            archive_format="raw_binary",
            checksum_url="https://example.com/jq.sha256",
        )
    }

    plan = MigrationPlanner(src, tgt, known_recipes=known).generate_plan()
    jq_app = next(a for a in plan.apps_to_install if a.name == "jq")
    assert jq_app.strategy == InstallStrategy.TARBALL_DOWNLOAD
    assert jq_app.checksum_url == "https://example.com/jq.sha256"


def test_executor_no_pam_edits_0750_tool_users_symlinks_and_byte_copy():
    src = ServerState(
        hostname="src.corp",
        os_release="RHEL 8",
        installed_rpms=["jq"],
        unmanaged_binaries=[
            BinaryItem(path="/opt/custom/mytool", is_rpm_owned=False, group_owner="ops_users"),
        ],
    )
    tgt = ServerState(hostname="tgt.corp", os_release="RHEL 9")
    plan = MigrationPlanner(src, tgt).generate_plan()

    src_mock = MagicMock()
    src_mock.read_bytes.return_value = b"\x7fELF\x02\x01\x01binary"
    tgt_mock = MagicMock()

    MigrationExecutor(plan, src_mock, tgt_mock).execute_plan()

    # Verify byte-for-byte binary copy
    src_mock.read_bytes.assert_called_with("/opt/custom/mytool")
    tgt_mock.write_bytes_privileged.assert_called_once()
    call_kwargs = tgt_mock.write_bytes_privileged.call_args.kwargs
    assert call_kwargs["mode"] == "0750"
    assert call_kwargs["group"] == "tool_users"

    priv_cmds = [str(c) for c in tgt_mock.run_privileged.mock_calls]
    # Verify dnf install in packages stage
    assert any("dnf install -y 'jq'" in c for c in priv_cmds)
    # Verify 0750 root:tool_users and /usr/local/bin symlink
    assert any("chmod 0750 '/opt/tools/bin/mytool'" in c and "ln -sf '/opt/tools/bin/mytool' '/usr/local/bin/mytool'" in c for c in priv_cmds)
    # Verify NO PAM / group.conf edits
    assert not any("/etc/security/group.conf" in c or "/etc/pam.d" in c for c in priv_cmds)


def test_executor_checksum_failure_raises_error():
    src = ServerState(
        hostname="src.corp",
        os_release="RHEL 8",
        unmanaged_binaries=[
            BinaryItem(path="/usr/local/bin/jq", is_rpm_owned=False, group_owner="tool_users"),
        ],
    )
    tgt = ServerState(hostname="tgt.corp", os_release="RHEL 9")
    known = {
        "jq": ToolRecipe(
            name="jq",
            version="1.7.1",
            download_url="https://example.com/jq",
            archive_format="raw_binary",
            checksum_url="https://example.com/jq.sha256",
        )
    }
    plan = MigrationPlanner(src, tgt, known_recipes=known).generate_plan()

    src_mock = MagicMock()
    tgt_mock = MagicMock()

    def fail_on_sha256(cmd, justification=""):
        if "sha256sum -c" in cmd:
            assert "|| true" not in cmd
            raise RuntimeError("Checksum mismatch")
        return ""

    tgt_mock.run_privileged.side_effect = fail_on_sha256

    with pytest.raises(RuntimeError, match="Checksum mismatch"):
        MigrationExecutor(plan, src_mock, tgt_mock, approved_stages={"binaries"}).execute_plan()


def test_cron_dependencies_and_profile_script_protections():
    mock_ssh = MagicMock()
    mock_ssh.run_cmd.side_effect = lambda cmd: "777" if "world.sh" in cmd else "644"
    mock_ssh.read_text.return_value = "export FOO=bar\n"

    src = ServerState(
        hostname="src.corp",
        os_release="RHEL 8",
        profile_scripts=[
            "/etc/profile.d/lang.sh",       # stock on target -> skip
            "/etc/profile.d/world.sh",      # world-writable -> skip
            "/etc/profile.d/declined.sh",   # user-declined -> skip
            "/etc/profile.d/custom.sh",     # safe non-stock -> keep
        ],
        root_crons=[
            CronEntry(user="root", line="0 1 * * * /home/alice@CORP.NET/nightly.sh"),
        ],
    )
    tgt = ServerState(
        hostname="tgt.corp",
        os_release="RHEL 9",
        profile_scripts=["/etc/profile.d/lang.sh"],
    )

    plan = MigrationPlanner(
        src, tgt, src_ssh=mock_ssh, declined_profile_scripts={"declined.sh"}
    ).generate_plan()

    assert plan.profile_scripts_to_deploy == ["/etc/profile.d/custom.sh"]
    assert len(plan.data_files_to_sync) == 1
    assert plan.data_files_to_sync[0].target_path == "/home/alice/nightly.sh"
    assert plan.data_files_to_sync[0].owner == "alice"


def test_verifier_checks_member_by_name_and_non_member_refusal():
    tgt_mock = MagicMock()

    def mock_run_cmd(cmd):
        if "ss -tulpn" in cmd:
            return "Netid State\ntcp LISTEN\n"
        if "getfacl /opt/tools" in cmd:
            return "# group: tool_users\ngroup:tool_users:r-x\n"
        if "getent group tool_users" in cmd:
            return "tool_users:x:1001:alice\n"
        return ""

    def mock_run_priv(cmd, just=""):
        if "ausearch" in cmd:
            return ""
        if "stat -c" in cmd:
            return "750:tool_users\n/opt/tools/bin/gh\n"
        if "nobody" in cmd:
            return "REFUSED\n"
        if "alice" in cmd:
            return "/usr/local/bin/gh\nMEMBER_OK\n"
        return ""

    tgt_mock.run_cmd.side_effect = mock_run_cmd
    tgt_mock.run_privileged.side_effect = mock_run_priv

    verifier = PostFlightVerifier(tgt_mock)
    res = verifier.verify(published_tools=["gh"])

    assert res["passed"] is True
    assert res["verified_member"] == "alice"
    assert res["tool_checks"]["gh"]["symlink_in_usr_local_bin"] is True
    assert res["tool_checks"]["gh"]["mode_no_world_access"] is True
    assert res["tool_checks"]["gh"]["non_member_refused"] is True
    assert res["tool_checks"]["gh"]["member_executable_by_name"] is True
