import json
import base64

# Self-contained remote collector script to run via python3 on the remote host in 1 round trip
REMOTE_COLLECTOR_SCRIPT = r'''
import os
import sys
import json
import subprocess
import glob
import re

def run_cmd(cmd):
    try:
        res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15)
        return res.stdout
    except Exception:
        return ""

def main():
    data = {}
    
    # 1. Hostname & OS
    hostname = run_cmd("hostname -f 2>/dev/null || hostname").strip()
    data["hostname"] = hostname

    os_pretty = ""
    if os.path.exists("/etc/os-release"):
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    os_pretty = line.split("=", 1)[1].strip().strip('"')
                    break
    if not os_pretty:
        os_pretty = run_cmd("cat /etc/redhat-release 2>/dev/null || uname -s").strip() or "Enterprise Linux"
    data["os_release"] = os_pretty

    # 2. Lineage manifest check
    manifest = None
    if os.path.exists("/etc/mcp-migration/manifest.json"):
        try:
            with open("/etc/mcp-migration/manifest.json") as f:
                manifest = json.load(f)
        except Exception:
            pass
    data["migration_manifest"] = manifest
    data["is_genesis"] = (manifest is None)

    # 3. Binaries & Data Files
    ENTERPRISE_PREFIXES = (
        "/opt/crowdstrike", "/opt/tanium", "/opt/dynatrace", "/opt/flexnetls",
        "/opt/splunkforwarder", "/opt/splunk", "/opt/qualys", "/opt/rapid7"
    )

    candidate_files = []
    for base_dir in ["/usr/local/bin", "/opt"]:
        if not os.path.exists(base_dir):
            continue
        for root, dirs, files in os.walk(base_dir):
            # Prune deeper than 3 levels from base
            rel = os.path.relpath(root, base_dir)
            depth = 0 if rel == "." else len(rel.split(os.sep))
            if depth >= 3:
                dirs[:] = []
            # Skip enterprise dirs
            dirs[:] = [d for d in dirs if not any(os.path.join(root, d).lower().startswith(p) for p in ENTERPRISE_PREFIXES)]
            for file in files:
                full_path = os.path.join(root, file)
                if any(full_path.lower().startswith(p) for p in ENTERPRISE_PREFIXES):
                    continue
                candidate_files.append(full_path)

    # In-process stat inspection
    binaries = []
    data_files = []
    app_group_map = {}
    executable_paths = []

    import pwd, grp
    for p in candidate_files:
        try:
            st = os.stat(p)
            mode_oct = oct(st.st_mode)[-3:]
            is_exec = bool(st.st_mode & 0o111)
            try:
                gname = grp.getgrgid(st.st_gid).gr_name
            except KeyError:
                gname = str(st.st_gid)
            try:
                uname = pwd.getpwuid(st.st_uid).pw_name
            except KeyError:
                uname = str(st.st_uid)

            if not is_exec:
                if p.startswith("/opt/scripts") or "/data" in p or p.endswith((".txt", ".json", ".conf", ".yaml", ".yml")):
                    data_files.append({
                        "source_path": p,
                        "target_path": p,
                        "mode": mode_oct,
                        "owner": uname,
                        "group": gname
                    })
            else:
                executable_paths.append((p, st.st_ino, st.st_nlink, mode_oct, gname, uname))
        except Exception:
            pass

    # Batch RPM check for executables
    rpm_ownership = {}
    if executable_paths:
        batch_paths = " ".join(f"'{p[0]}'" for p in executable_paths)
        raw_rpm = run_cmd(f"rpm -qf {batch_paths} 2>/dev/null").splitlines()
        for idx, (p, ino, nlink, mode_oct, gname, uname) in enumerate(executable_paths):
            rpm_q = raw_rpm[idx] if idx < len(raw_rpm) else ""
            is_rpm = bool(rpm_q and "not owned by any package" not in rpm_q and not rpm_q.startswith("error:"))
            rpm_ownership[p] = (is_rpm, rpm_q if is_rpm else None)

    for p, ino, nlink, mode_oct, gname, uname in executable_paths:
        is_rpm, pkg_name = rpm_ownership.get(p, (False, None))
        app_name = os.path.basename(p).lower()
        if gname not in ("root", "wheel", "bin"):
            app_group_map[app_name] = gname

        binaries.append({
            "path": p,
            "is_rpm_owned": is_rpm,
            "package_name": pkg_name,
            "group_owner": gname,
            "acl_groups": [],
            "permissions": mode_oct,
            "inode": ino,
            "link_count": nlink,
            "is_executable": True,
            "mode": mode_oct
        })

    data["unmanaged_binaries"] = binaries
    data["data_files"] = data_files

    # 4. Custom Groups
    custom_groups = []
    RESERVED = {"root", "bin", "daemon", "sys", "adm", "tty", "disk", "lp", "mail", "news", "uucp", "man", "proxy", "kmem", "dialout", "fax", "voice", "cdrom", "floppy", "tape", "sudo", "audio", "dip", "www-data", "backup", "operator", "list", "irc", "src", "gnats", "shadow", "utmp", "video", "sasl", "plugdev", "staff", "games", "users", "nogroup", "systemd-journal", "systemd-network", "systemd-resolve", "wheel", "nobody", "nfsnobody", "mcp-migrate"}
    try:
        import grp
        for g in grp.getgrall():
            if g.gr_name in RESERVED:
                continue
            is_custom = (g.gr_gid >= 1000) or any(p in g.gr_name for p in ("_users", "_ops", "_dev", "_admin", "tool_users"))
            if is_custom:
                associated = [app for app, grp_name in app_group_map.items() if grp_name == g.gr_name]
                custom_groups.append({
                    "name": g.gr_name,
                    "gid": g.gr_gid,
                    "members": list(g.gr_mem),
                    "associated_apps": associated
                })
    except Exception:
        pass
    data["custom_groups"] = custom_groups

    # 5. Root Crons
    root_crons = []
    raw_crons = run_cmd("crontab -l -u root 2>/dev/null").splitlines()
    for line in raw_crons:
        line = line.strip()
        if line and not line.startswith("#"):
            root_crons.append({"user": "root", "line": line, "is_custom": True})
    data["root_crons"] = root_crons

    # 6. Running Services
    services = []
    raw_svc = run_cmd("systemctl list-units --type=service --state=running --no-legend --no-pager 2>/dev/null").splitlines()
    for s in raw_svc:
        parts = s.split()
        if len(parts) >= 4:
            services.append({"name": parts[0], "state": parts[3], "is_enabled": True})
    data["running_services"] = services

    # 7. Vendor Trees
    v_trees = [d.rstrip("/") for d in glob.glob("/opt/*/")]
    data["vendor_trees"] = v_trees

    # 8. Installed RPMs
    raw_rpms = [r.strip() for r in run_cmd("rpm -qa --qf '%{NAME}\n' 2>/dev/null").splitlines() if r.strip()]
    data["installed_rpms"] = raw_rpms

    # 9. Module Streams
    module_streams = []
    MOD_RE = re.compile(r"^([a-zA-Z0-9_\-]+)\s+([a-zA-Z0-9_\.\-]+)\s+\[e\]\s*(.*)$")
    raw_mods = run_cmd("dnf module list --enabled 2>/dev/null").splitlines()
    for m_line in raw_mods:
        m = MOD_RE.search(m_line.strip())
        if m:
            module_streams.append({"name": m.group(1), "stream": m.group(2), "profile": m.group(3) or "common"})
    data["module_streams"] = module_streams

    # 10. Profile Scripts
    data["profile_scripts"] = glob.glob("/etc/profile.d/*.sh")

    # Output clean JSON
    print(json.dumps(data))

if __name__ == "__main__":
    main()
'''

class RemoteCollector:
    @classmethod
    def get_collector_command(cls) -> str:
        # Base64 encode the script to avoid shell escaping issues
        encoded = base64.b64encode(REMOTE_COLLECTOR_SCRIPT.strip().encode("utf-8")).decode("ascii")
        return f"python3 -c 'import base64; exec(base64.b64decode(\"{encoded}\").decode(\"utf-8\"))' 2>/dev/null"
