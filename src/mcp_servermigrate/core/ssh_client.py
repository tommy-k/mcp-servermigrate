import io
import uuid
import paramiko
from typing import Optional
from mcp_servermigrate.core.security import EphemeralCredentialVault

class SSHConnection:
    def __init__(self, host: str, user: str = "root", port: int = 22, key_filename: Optional[str] = None):
        self.host = host
        self.user = user
        self.port = port
        self.key_filename = key_filename
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self._is_connected = False
        self._sftp: Optional[paramiko.SFTPClient] = None
        self._current_user: Optional[str] = None

    def connect(self) -> None:
        if not self._is_connected:
            self.client.connect(
                hostname=self.host,
                port=self.port,
                username=self.user,
                key_filename=self.key_filename,
                timeout=10
            )
            self._is_connected = True

    def close(self) -> None:
        if self._sftp:
            try:
                self._sftp.close()
            except Exception:
                pass
            self._sftp = None
        if self._is_connected:
            self.client.close()
            self._is_connected = False

    def get_sftp(self) -> paramiko.SFTPClient:
        self.connect()
        if self._sftp is None:
            self._sftp = self.client.open_sftp()
        return self._sftp

    def whoami(self) -> str:
        if not self._current_user:
            self._current_user = self.run_cmd("whoami").strip() or self.user
        return self._current_user

    def run_cmd(self, command: str) -> str:
        self.connect()
        _, stdout, stderr = self.client.exec_command(command)
        return stdout.read().decode("utf-8")

    def run_sudo_cmd(self, command: str, justification: str = "Privileged operation") -> str:
        self.connect()
        vault = EphemeralCredentialVault.get_vault()
        
        if not vault.confirm_privileged_action(self.host, command, justification):
            raise PermissionError(f"Execution of '{command}' on {self.host} was rejected by operator.")

        password = vault.get_sudo_password(self.host)
        
        # SEC-1: Use 'sudo -k -S -p \'\'' so password prompt is deterministic and consumed
        stdin, stdout, stderr = self.client.exec_command(f"sudo -k -S -p '' {command}")
        stdin.write(f"{password}\n")
        stdin.flush()
        
        exit_status = stdout.channel.recv_exit_status()
        out = stdout.read().decode("utf-8")
        err = stderr.read().decode("utf-8")
        
        if exit_status != 0 and err.strip():
            # If standard error has error message, raise
            raise RuntimeError(f"Sudo command failed (code {exit_status}): {err.strip()}")
        return out

    def run_privileged(self, command: str, justification: str = "Administrative operation") -> str:
        """Runs command as root directly if connected as root, otherwise escalates via sudo."""
        if self.user == "root" or self.whoami() == "root":
            return self.run_cmd(command)
        return self.run_sudo_cmd(command, justification)

    def run_with_sudo_fallback(self, command: str, justification: str = "Operation requiring elevated privileges") -> str:
        """Attempts normal execution first; if permission denied occurs, automatically escalates to sudo."""
        if self.user == "root" or self.whoami() == "root":
            return self.run_cmd(command)
        
        out = self.run_cmd(command)
        if "permission denied" in out.lower() or "operation not permitted" in out.lower() or "authentication failure" in out.lower():
            return self.run_sudo_cmd(command, justification)
        return out

    def read_text(self, path: str, use_sudo_fallback: bool = True) -> str:
        """Reads text from remote path, falling back to sudo if permissions prevent direct read (BUG-18)."""
        try:
            sftp = self.get_sftp()
            with sftp.open(path, "r") as f:
                return f.read().decode("utf-8")
        except Exception:
            if use_sudo_fallback:
                return self.run_privileged(f"cat '{path}'", f"Read privileged file {path}")
            raise

    def write_text_privileged(
        self,
        path: str,
        content: str,
        mode: str = "0644",
        owner: str = "root",
        group: str = "root"
    ) -> None:
        """
        SEC-1: Stage unprivileged in /tmp/mcp-upload-<uuid> and place with sudo install.
        Never pipe sudo password through sudo -S ... cat > dest.
        """
        staging_file = f"/tmp/mcp-upload-{uuid.uuid4().hex}"
        try:
            sftp = self.get_sftp()
            with sftp.open(staging_file, "w") as f:
                f.write(content)
        except Exception:
            # Fallback staging via echo/printf without sudo
            import base64
            b64_content = base64.b64encode(content.encode("utf-8")).decode("ascii")
            self.run_cmd(f"echo '{b64_content}' | base64 -d > {staging_file}")

        # Ensure parent directory exists on target
        parent_dir = path.rsplit("/", 1)[0]
        if parent_dir:
            self.run_privileged(f"mkdir -p '{parent_dir}'", f"Create directory {parent_dir}")

        # Install file into final location with correct mode, owner, and group
        self.run_privileged(
            f"install -m {mode} -o {owner} -g {group} '{staging_file}' '{path}' && rm -f '{staging_file}'",
            f"Place privileged file {path}"
        )
