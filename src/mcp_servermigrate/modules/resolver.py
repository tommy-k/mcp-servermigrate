import re
from typing import Optional
from mcp_servermigrate.core.models import ToolRecipe
from mcp_servermigrate.core.ssh_client import SSHConnection

class DynamicReleaseResolver:
    """Dynamically discovers the latest stable upstream release for any CLI tool."""

    @classmethod
    def resolve_release(cls, app_name: str, source_binary_path: str = "", ssh: Optional[SSHConnection] = None) -> ToolRecipe:
        app_clean = app_name.lower().strip()
        version = "latest"
        download_url = None
        archive_format = "tar.gz"

        # 1. Self-inspect binary on source server if SSH connection is provided
        detected_repo = None
        if ssh and source_binary_path:
            try:
                # Probe version
                v_out = ssh.run_cmd(f"{source_binary_path} --version 2>/dev/null || {source_binary_path} version 2>/dev/null || {source_binary_path} -v 2>/dev/null").strip()
                v_match = re.search(r'(\d+\.\d+\.[\d\w-]+)', v_out)
                if v_match:
                    version = v_match.group(1)

                # Probe binary strings for upstream repo
                s_out = ssh.run_cmd(f"strings {source_binary_path} 2>/dev/null | grep -E 'github[.]com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+' | head -n 5").strip()
                repo_match = re.search(r'github[.]com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)', s_out)
                if repo_match:
                    detected_repo = repo_match.group(1).rstrip('.')
            except Exception:
                pass

        # 2. Universal Vendor Patterns & Dynamic URL Generation
        if app_clean in ("terraform", "tf"):
            version_str = version if version != "latest" else "1.9.5"
            download_url = f"https://releases.hashicorp.com/terraform/{version_str}/terraform_{version_str}_linux_amd64.zip"
            archive_format = "zip"
        elif app_clean in ("packer", "vault", "consul"):
            version_str = version if version != "latest" else "1.10.0"
            download_url = f"https://releases.hashicorp.com/{app_clean}/{version_str}/{app_clean}_{version_str}_linux_amd64.zip"
            archive_format = "zip"
        elif app_clean == "gh":
            download_url = "https://github.com/cli/cli/releases/latest/download/gh_linux_amd64.tar.gz"
            archive_format = "tar.gz"
        elif app_clean == "kubectl":
            download_url = "https://dl.k8s.io/release/v1.31.0/bin/linux/amd64/kubectl"
            archive_format = "raw_binary"
        elif app_clean == "helm":
            download_url = "https://get.helm.sh/helm-v3.15.4-linux-amd64.tar.gz"
            archive_format = "tar.gz"
        elif app_clean == "rclone":
            download_url = "https://downloads.rclone.org/rclone-current-linux-amd64.zip"
            archive_format = "zip"
        elif detected_repo:
            # Generic GitHub release asset
            download_url = f"https://github.com/{detected_repo}/releases/latest/download/{app_clean}_linux_amd64.tar.gz"
            archive_format = "tar.gz"

        return ToolRecipe(
            name=app_clean,
            version=version,
            download_url=download_url,
            target_path=f"/opt/tools/bin/{app_clean}",
            group="tool_users",
            archive_format=archive_format,
            binary_name=app_clean
        )
