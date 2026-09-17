import os
from mcp_servermigrate.core.models import ServerState, BinaryItem, CronEntry, ServiceItem, GroupItem
from mcp_servermigrate.core.ssh_client import SSHConnection
from mcp_servermigrate.modules.lineage import LineageManager

class DiscoveryEngine:
    def __init__(self, ssh: SSHConnection):
        self.ssh = ssh

    def discover_state(self) -> ServerState:
        hostname = self.ssh.run_cmd("hostname -f").strip() or self.ssh.host
        os_release = self.ssh.run_cmd(
            'source /etc/os-release 2>/dev/null && echo "$PRETTY_NAME" || cat /etc/redhat-release 2>/dev/null || uname -s'
        ).strip() or "Enterprise Linux"

        # 1. Check on-server migration lineage (Genesis vs Generational)
        manifest = LineageManager.read_manifest_from_host(self.ssh)
        is_genesis = manifest is None

        # 2. Discover unmanaged binaries in /opt and /usr/local/bin with group ownership & ACLs
        binaries: list[BinaryItem] = []
        app_group_map: dict[str, str] = {}
        raw_paths = self.ssh.run_cmd("find /usr/local/bin /opt -maxdepth 3 -type f -executable 2>/dev/null").splitlines()
        for b_path in raw_paths:
            b_path = b_path.strip()
            if not b_path:
                continue
            rpm_query = self.ssh.run_cmd(f"rpm -qf {b_path} 2>/dev/null").strip()
            is_rpm = "is not owned by any package" not in rpm_query and not rpm_query.startswith("error:")
            ls_info = self.ssh.run_cmd(f"ls -lZ {b_path} 2>/dev/null").strip().split()

            # Group owner & ACL inspection
            group_owner = self.ssh.run_cmd(f"stat -c '%G' {b_path} 2>/dev/null").strip() or "root"
            raw_acls = self.ssh.run_cmd(f"getfacl -c {b_path} 2>/dev/null").splitlines()
            acl_groups = []
            for line in raw_acls:
                if line.startswith("group:") and not line.startswith("group::"):
                    parts = line.split(":")
                    if len(parts) >= 2 and parts[1].strip():
                        acl_groups.append(parts[1].strip())

            app_name = os.path.basename(b_path).lower()
            if group_owner not in ("root", "wheel", "bin"):
                app_group_map[app_name] = group_owner
            elif acl_groups:
                app_group_map[app_name] = acl_groups[0]

            binaries.append(BinaryItem(
                path=b_path,
                is_rpm_owned=is_rpm,
                package_name=rpm_query if is_rpm else None,
                group_owner=group_owner,
                acl_groups=acl_groups,
                permissions=ls_info[0] if ls_info else "unknown",
                selinux_context=ls_info[3] if len(ls_info) > 3 else "unknown"
            ))

        # 3. Discover custom & application-specific local groups
        custom_groups: list[GroupItem] = []
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

                # Filter for custom user/role groups (GID >= 1000 or specific naming patterns)
                is_custom = (
                    (gid is not None and gid >= 1000) or
                    any(p in g_name for p in ("_users", "_ops", "_dev", "_admin", "tool_users"))
                ) and g_name not in ("nobody", "nfsnobody")

                if is_custom:
                    associated = [app for app, grp in app_group_map.items() if grp == g_name]
                    custom_groups.append(GroupItem(
                        name=g_name,
                        gid=gid,
                        members=members,
                        associated_apps=associated
                    ))

        # 4. Discover custom root crons
        root_crons: list[CronEntry] = []
        try:
            raw_crons = self.ssh.run_privileged("crontab -l -u root 2>/dev/null", "Audit root crontab").splitlines()
            for line in raw_crons:
                line = line.strip()
                if line and not line.startswith("#"):
                    root_crons.append(CronEntry(user="root", line=line, is_custom=True))
        except Exception:
            pass

        # 5. Discover running services
        services: list[ServiceItem] = []
        raw_services = self.ssh.run_cmd("systemctl list-units --type=service --state=running --no-legend --no-pager 2>/dev/null").splitlines()
        for s in raw_services:
            parts = s.split()
            if len(parts) >= 4:
                services.append(ServiceItem(name=parts[0], state=parts[3], is_enabled=True))

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
            root_crons=root_crons,
            running_services=services,
            profile_scripts=profile_scripts
        )
