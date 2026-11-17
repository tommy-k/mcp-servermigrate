from typing import Dict, Any, List, Optional
from mcp_servermigrate.core.ssh_client import SSHConnection
from mcp_servermigrate.modules.lineage import LineageManager
from rich.console import Console

console = Console()


class PostFlightVerifier:
    def __init__(self, target_conn: SSHConnection):
        self.tgt = target_conn

    def _get_published_tools(self, published_tools: Optional[List[str]]) -> List[str]:
        if published_tools is not None:
            return published_tools
        manifest = LineageManager.read_manifest_from_host(self.tgt)
        if manifest and "tool_users" in manifest.application_groups:
            return list(manifest.application_groups["tool_users"])
        raw = self.tgt.run_cmd("ls -1 /opt/tools/bin 2>/dev/null").splitlines()
        return [t.strip() for t in raw if t.strip()]

    def _find_tool_users_member(self, member_user: Optional[str]) -> Optional[str]:
        if member_user:
            return member_user
        grp_line = self.tgt.run_cmd("getent group tool_users").strip()
        if grp_line and ":" in grp_line:
            members = [m.strip() for m in grp_line.split(":")[-1].split(",") if m.strip()]
            if members:
                return members[0]
        return None

    def verify(
        self,
        published_tools: Optional[List[str]] = None,
        member_user: Optional[str] = None,
        non_member_user: str = "nobody",
    ) -> Dict[str, Any]:
        console.print("[bold yellow]🔍 Running Post-Flight Verification on Target Server...[/bold yellow]")
        results: Dict[str, Any] = {}

        # 1. SELinux AVC check (do not hide command errors with || true)
        avc_check = self.tgt.run_privileged(
            "sh -c 'out=$(ausearch -m avc -ts recent 2>&1); rc=$?; if [ $rc -eq 1 ]; then echo \"\"; elif [ $rc -eq 0 ]; then echo \"$out\" | grep -i denied || echo \"\"; else echo \"ERROR:$out\"; fi'",
            "Audit SELinux denials"
        ).strip()
        results["selinux_denials_found"] = bool(avc_check and not avc_check.startswith("ERROR:"))
        if avc_check.startswith("ERROR:"):
            results["selinux_audit_error"] = avc_check

        # 2. Listening sockets
        ports = self.tgt.run_cmd("ss -tulpn").splitlines()
        results["open_sockets_count"] = max(0, len(ports) - 1)

        # 3. Tool directory ACL & mode check (no world permissions)
        acl_check = self.tgt.run_cmd("getfacl /opt/tools")
        results["tools_acl_configured"] = "tool_users" in acl_check

        # 4. Verify each published tool: symlink in /usr/local/bin, 0750 mode, member access, non-member refusal
        tools = self._get_published_tools(published_tools)
        real_member = self._find_tool_users_member(member_user)

        tool_checks: Dict[str, Dict[str, Any]] = {}
        all_tools_ok = True

        for tool in tools:
            bin_path = f"/opt/tools/bin/{tool}"
            link_path = f"/usr/local/bin/{tool}"

            # Check symlink & mode (no world execute)
            stat_out = self.tgt.run_privileged(
                f"stat -c '%a:%G' '{bin_path}' && readlink -f '{link_path}'",
                f"Verify mode and symlink for {tool}"
            ).splitlines()
            mode_ok = False
            symlink_ok = False
            if len(stat_out) >= 2:
                mode_grp = stat_out[0].strip()
                resolved_link = stat_out[1].strip()
                mode_str = mode_grp.split(":")[0]
                try:
                    mode_ok = (int(mode_str, 8) & 0o007) == 0 and "tool_users" in mode_grp
                except ValueError:
                    mode_ok = False
                symlink_ok = (resolved_link == bin_path)

            # Check non-member is refused execution
            refused_out = self.tgt.run_privileged(
                f"su -s /bin/bash '{non_member_user}' -c \"test -x '{bin_path}' && echo ALLOWED || echo REFUSED\"",
                f"Verify non-member {non_member_user} is refused {tool}"
            ).strip()
            non_member_refused = ("REFUSED" in refused_out and "ALLOWED" not in refused_out)

            # Check real member can find tool by name on login $PATH and execute it
            member_exec_ok: Optional[bool] = None
            if real_member:
                member_out = self.tgt.run_privileged(
                    f"su -s /bin/bash -l '{real_member}' -c \"command -v '{tool}' && test -x \\\"\\$(command -v '{tool}')\\\" && echo MEMBER_OK\"",
                    f"Verify member {real_member} can resolve and execute {tool} by name"
                ).strip()
                member_exec_ok = ("MEMBER_OK" in member_out)

            tool_ok = mode_ok and symlink_ok and non_member_refused and (member_exec_ok is not False)
            if not tool_ok:
                all_tools_ok = False

            tool_checks[tool] = {
                "mode_no_world_access": mode_ok,
                "symlink_in_usr_local_bin": symlink_ok,
                "non_member_refused": non_member_refused,
                "member_executable_by_name": member_exec_ok,
                "ok": tool_ok,
            }

        results["tool_checks"] = tool_checks
        results["verified_member"] = real_member
        results["passed"] = bool(
            results["tools_acl_configured"]
            and not results["selinux_denials_found"]
            and all_tools_ok
        )
        return results
