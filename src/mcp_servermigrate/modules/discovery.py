import os
import re
import json
from typing import List, Dict, Optional, Set
from mcp_servermigrate.core.models import (
    ServerState, BinaryItem, DataFileItem, CronEntry,
    ServiceItem, GroupItem, ModuleStreamItem
)
from mcp_servermigrate.core.ssh_client import SSHConnection
from mcp_servermigrate.core.policy import (
    is_enterprise_path,
    ENTERPRISE_PATH_PREFIXES,
    GROUP_NAME_RE,
    RESERVED_GROUPS,
    MODULE_STREAM_RE
)
from mcp_servermigrate.modules.lineage import LineageManager
from mcp_servermigrate.modules.collector import RemoteCollector

class DiscoveryEngine:
    def __init__(self, ssh: SSHConnection):
        self.ssh = ssh

    def discover_state(self) -> ServerState:
        # ⚡ Fast Path: 1-Shot Remote Collector (1 SSH round-trip)
        try:
            collector_cmd = RemoteCollector.get_collector_command()
            raw_output = self.ssh.run_cmd(collector_cmd).strip()
            if raw_output and raw_output.startswith("{") and raw_output.endswith("}"):
                data = json.loads(raw_output)
                if not data.get("hostname"):
                    data["hostname"] = self.ssh.host
                return ServerState.model_validate(data)
        except Exception:
            # Graceful fallback to multi-command discovery if python3 is unavailable
            pass

        # 🐢 Fallback Path: Sequential multi-command discovery
        hostname = self.ssh.run_cmd("hostname -f 2>/dev/null || hostname").strip() or self.ssh.host
        os_release = self.ssh.run_cmd(
            'source /etc/os-release 2>/dev/null && echo "$PRETTY_NAME" || cat /etc/redhat-release 2>/dev/null || uname -s'
        ).strip() or "Enterprise Linux"

        # 1. Check on-server migration lineage (Genesis vs Generational)
        manifest = LineageManager.read_manifest_from_host(self.ssh)
        is_genesis = manifest is None

        # 2. Discover files in /usr/local/bin and /opt using stat mode bits (BUG-5, BUG-6, BUG-7)
        binaries: List[BinaryItem] = []
        data_files: List[DataFileItem] = []
        app_group_map: Dict[str, str] = {}

        # Stat batch: inode|link_count|octal_mode|group|owner|path
        stat_output = self.ssh.run_cmd(
            "find /usr/local/bin /opt -maxdepth 3 -type f -exec stat -c '%i|%h|%a|%G|%U|%n' {} + 2>/dev/null"
        ).splitlines()

        for line in stat_output:
            line = line.strip()
            if not line or "|" not in line:
                continue
            parts = line.split("|", 5)
            if len(parts) < 6:
                continue

            try:
                inode = int(parts[0])
                link_count = int(parts[1])
            except ValueError:
                inode = None
                link_count = 1

            mode_str = parts[2]
            group_owner = parts[3]
            user_owner = parts[4]
            file_path = parts[5].strip()

            # Skip enterprise agent paths (Dynatrace, CrowdStrike, Tanium, etc.)
            if is_enterprise_path(file_path) or any(
                file_path.lower().startswith(p.lower()) for p in ENTERPRISE_PATH_PREFIXES
            ):
                continue

            # Determine execute bits
            try:
                mode_val = int(mode_str, 8)
                is_exec = (mode_val & 0o111) != 0
            except ValueError:
                is_exec = False

            if not is_exec:
                # Script data file (BUG-6)
                if file_path.startswith("/opt/scripts") or "/data" in file_path or file_path.endswith((".txt", ".json", ".conf", ".yaml", ".yml")):
                    data_files.append(DataFileItem(
                        source_path=file_path,
                        target_path=file_path,
                        mode=mode_str,
                        owner=user_owner,
                        group=group_owner
                    ))
                continue

            # It's an executable file
            rpm_query = self.ssh.run_cmd(f"rpm -qf '{file_path}' 2>/dev/null").strip()
            is_rpm = "is not owned by any package" not in rpm_query and not rpm_query.startswith("error:")

            # ACL inspection
            raw_acls = self.ssh.run_cmd(f"getfacl -c '{file_path}' 2>/dev/null").splitlines()
            acl_groups: List[str] = []
            for acl_line in raw_acls:
                if acl_line.startswith("group:") and not acl_line.startswith("group::"):
                    g_parts = acl_line.split(":")
                    if len(g_parts) >= 2 and g_parts[1].strip():
                        acl_groups.append(g_parts[1].strip())

            app_name = os.path.basename(file_path).lower()
            if group_owner not in ("root", "wheel", "bin"):
                app_group_map[app_name] = group_owner
            elif acl_groups:
                app_group_map[app_name] = acl_groups[0]

            binaries.append(BinaryItem(
                path=file_path,
                is_rpm_owned=is_rpm,
                package_name=rpm_query if is_rpm else None,
                group_owner=group_owner,
                acl_groups=acl_groups,
                permissions=mode_str,
                inode=inode,
                link_count=link_count,
                is_executable=True,
                mode=mode_str
            ))

        # 3. Discover custom local groups
        custom_groups: List[GroupItem] = []
        raw_groups = self.ssh.run_cmd("getent group 2>/dev/null || cat /etc/group 2>/dev/null").splitlines()
        for g_line in raw_groups:
            g_line = g_line.strip()
            if not g_line or g_line.startswith("#"):
                continue
            parts = g_line.split(":")
            if len(parts) >= 3:
                g_name = parts[0]
                try:
                    gid = int(parts[2])
                except ValueError:
                    gid = None

                members = parts[3].split(",") if len(parts) > 3 and parts[3].strip() else []

                is_custom = (
                    (gid is not None and gid >= 1000) or
                    any(p in g_name for p in ("_users", "_ops", "_dev", "_admin", "tool_users"))
                ) and g_name not in RESERVED_GROUPS

                if is_custom:
                    associated = [app for app, grp in app_group_map.items() if grp == g_name]
                    custom_groups.append(GroupItem(
                        name=g_name,
                        gid=gid,
                        members=members,
                        associated_apps=associated
                    ))

        # 4. Discover custom root crons
        root_crons: List[CronEntry] = []
        try:
            raw_crons = self.ssh.run_privileged("crontab -l -u root 2>/dev/null", "Audit root crontab").splitlines()
            for cron_line in raw_crons:
                cron_line = cron_line.strip()
                if cron_line and not cron_line.startswith("#"):
                    root_crons.append(CronEntry(user="root", line=cron_line, is_custom=True))
        except Exception:
            pass

        # 5. Discover running services
        services: List[ServiceItem] = []
        raw_services = self.ssh.run_cmd("systemctl list-units --type=service --state=running --no-legend --no-pager 2>/dev/null").splitlines()
        for s in raw_services:
            s_parts = s.split()
            if len(s_parts) >= 4:
                services.append(ServiceItem(name=s_parts[0], state=s_parts[3], is_enabled=True))

        # 6. Discover vendor trees in /opt
        vendor_trees = [
            t.strip().rstrip("/") for t in self.ssh.run_cmd("ls -d /opt/*/ 2>/dev/null").splitlines() if t.strip()
        ]

        # 7. Discover installed RPMs
        installed_rpms = [
            r.strip() for r in self.ssh.run_cmd("rpm -qa --qf '%{NAME}\n' 2>/dev/null").splitlines() if r.strip()
        ]

        # 8. Discover module streams (BUG-13)
        module_streams: List[ModuleStreamItem] = []
        try:
            dnf_mod_raw = self.ssh.run_cmd("dnf module list --enabled 2>/dev/null").splitlines()
            for d_line in dnf_mod_raw:
                d_line = d_line.strip()
                m = MODULE_STREAM_RE.search(d_line)
                if m:
                    mod_name, mod_stream, mod_profile = m.group(1), m.group(2), m.group(3)
                    module_streams.append(ModuleStreamItem(name=mod_name, stream=mod_stream, profile=mod_profile or "common"))
        except Exception:
            pass

        profile_scripts = [
            p.strip() for p in self.ssh.run_cmd("ls -1 /etc/profile.d/*.sh 2>/dev/null").splitlines() if p.strip()
        ]

        return ServerState(
            hostname=hostname,
            os_release=os_release,
            is_genesis=is_genesis,
            migration_manifest=manifest,
            custom_groups=custom_groups,
            unmanaged_binaries=binaries,
            data_files=data_files,
            module_streams=module_streams,
            vendor_trees=vendor_trees,
            installed_rpms=installed_rpms,
            root_crons=root_crons,
            running_services=services,
            profile_scripts=profile_scripts
        )
