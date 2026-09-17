import json
from datetime import datetime, timezone
from typing import Optional
from mcp_servermigrate.core.models import ServerMigrationManifest, ToolRecipe
from mcp_servermigrate.core.ssh_client import SSHConnection

MANIFEST_PATH = "/etc/mcp-migration/manifest.json"
SKILL_PATH = "/etc/mcp-migration/SKILL.md"

class LineageManager:
    @staticmethod
    def read_manifest_from_host(ssh: SSHConnection) -> Optional[ServerMigrationManifest]:
        """Reads existing migration lineage from /etc/mcp-migration/manifest.json if present."""
        try:
            check = ssh.run_cmd(f"test -f {MANIFEST_PATH} && echo 'EXISTS' || echo 'MISSING'").strip()
            if "EXISTS" not in check:
                return None
            raw_json = ssh.run_privileged(f"cat {MANIFEST_PATH} 2>/dev/null", "Read migration manifest").strip()
            if not raw_json:
                return None
            data = json.loads(raw_json)
            return ServerMigrationManifest.model_validate(data)
        except Exception:
            return None

    @staticmethod
    def generate_skill_markdown(manifest: ServerMigrationManifest) -> str:
        """Generates the human- and agent-readable /etc/mcp-migration/SKILL.md on-server skill."""
        tools_list = "\n".join([
            f"- **{name}** ({recipe.version}): Target `{recipe.target_path}` | Role Group: `{recipe.group}` | Source: `{recipe.download_url or 'Source Sync'}`"
            for name, recipe in manifest.tools.items()
        ]) or "- No custom external tools registered."

        groups_list = "\n".join([
            f"- **Group `{grp}`**: Controls access to -> {', '.join([f'`{app}`' for app in apps])}"
            for grp, apps in manifest.application_groups.items()
        ]) or "- `tool_users`: Default access to all `/opt/tools/bin/` binaries."

        rules_list = "\n".join([f"{i+1}. {rule}" for i, rule in enumerate(manifest.learned_rules)]) or (
            "1. **SELinux Context**: Always maintain `bin_t` on `/opt/tools/bin/` so domain users can execute binaries.\n"
            "2. **POSIX ACLs**: Ensure default inheritance (`-d`) is active for group `tool_users` on `/opt/tools`.\n"
            "3. **PAM Bridging**: AD `%Domain Users` is dynamically attached to `tool_users` via `/etc/security/group.conf`.\n"
            "4. **User Onboarding Contract**: Future onboarding agents can assign users to groups listed in 'Application Groups' above to grant specific tool rights."
        )

        return f"""# 🧠 Server Migration Lineage & Operational Skill

This host was provisioned and configured by `mcp-servermigrate`.
Future AI migration agents and User Onboarding agents should inspect this file to inherit verified recipes and assign users to the appropriate groups.

## Metadata
- **Generation**: {manifest.generation}
- **Parent Origin Host**: `{manifest.parent_host}`
- **Migration Completed**: `{manifest.migration_timestamp}`
- **Primary Tool Directory**: `{manifest.acl_path}/bin`

## 👥 Application Groups (Onboarding Contract)
{groups_list}

## 🛠️ Installed Applications & Recipes
{tools_list}

## 🔒 Access Control & RBAC
- **Default Local Group**: `{manifest.local_group}`
- **Default Active Directory Group**: `{manifest.ad_group}`
- **Managed Path**: `{manifest.acl_path}`

## 📋 Learned Operational Rules
{rules_list}
"""

    @classmethod
    def plant_lineage(cls, ssh: SSHConnection, manifest: ServerMigrationManifest) -> None:
        """Plants both the machine-readable manifest and the agent SKILL.md on the target server."""
        ssh.run_privileged("mkdir -p /etc/mcp-migration && chmod 750 /etc/mcp-migration", "Create migration lineage path")
        manifest_json = manifest.model_dump_json(indent=2)
        skill_md = cls.generate_skill_markdown(manifest)

        ssh.run_privileged(
            f"cat << 'EOF' > {MANIFEST_PATH}\n{manifest_json}\nEOF\nchmod 644 {MANIFEST_PATH}",
            "Plant machine-readable migration manifest"
        )
        ssh.run_privileged(
            f"cat << 'EOF' > {SKILL_PATH}\n{skill_md}\nEOF\nchmod 644 {SKILL_PATH}",
            "Plant agent reasoning skill on server"
        )
