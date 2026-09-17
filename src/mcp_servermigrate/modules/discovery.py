from mcp_servermigrate.core.models import ServerState, BinaryItem, CronEntry, ServiceItem
from mcp_servermigrate.core.ssh_client import SSHConnection
from mcp_servermigrate.modules.lineage import LineageManager

class DiscoveryEngine:
    def __init__(self, ssh: SSHConnection):
        self.ssh = ssh

    def discover_state(self) -> ServerState:
        hostname = self.ssh.run_cmd("hostname -f").strip() or self.ssh.host
        os_release = self.ssh.run_cmd("cat /etc/redhat-release 2>/dev/null").strip() or "Unknown Linux"

        # 1. Check for on-server migration lineage (Genesis vs Generational)
        manifest = LineageManager.read_manifest_from_host(self.ssh)
        is_genesis = manifest is None

        # 2. Discover unmanaged binaries in /opt and /usr/local/bin
        binaries: list[BinaryItem] = []
        raw_paths = self.ssh.run_cmd("find /usr/local/bin /opt -maxdepth 3 -type f -executable 2>/dev/null").splitlines()
        for b_path in raw_paths:
            b_path = b_path.strip()
            if not b_path:
                continue
            rpm_query = self.ssh.run_cmd(f"rpm -qf {b_path} 2>/dev/null").strip()
            is_rpm = "is not owned by any package" not in rpm_query and not rpm_query.startswith("error:")
            ls_info = self.ssh.run_cmd(f"ls -lZ {b_path} 2>/dev/null").strip().split()

            binaries.append(BinaryItem(
                path=b_path,
                is_rpm_owned=is_rpm,
                package_name=rpm_query if is_rpm else None,
                permissions=ls_info[0] if ls_info else "unknown",
                selinux_context=ls_info[3] if len(ls_info) > 3 else "unknown"
            ))

        # 3. Discover custom root crons
        root_crons: list[CronEntry] = []
        try:
            raw_crons = self.ssh.run_sudo_cmd("crontab -l -u root 2>/dev/null", "Audit root crontab").splitlines()
            for line in raw_crons:
                line = line.strip()
                if line and not line.startswith("#"):
                    root_crons.append(CronEntry(user="root", line=line, is_custom=True))
        except Exception:
            pass

        # 4. Discover running services
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
            unmanaged_binaries=binaries,
            root_crons=root_crons,
            running_services=services,
            profile_scripts=profile_scripts
        )
