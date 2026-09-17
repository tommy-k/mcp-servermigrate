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
        if self._is_connected:
            self.client.close()
            self._is_connected = False

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
        
        stdin, stdout, stderr = self.client.exec_command(f"sudo -S -p '' {command}")
        stdin.write(f"{password}\n")
        stdin.flush()
        
        exit_status = stdout.channel.recv_exit_status()
        out = stdout.read().decode("utf-8")
        err = stderr.read().decode("utf-8")
        
        if exit_status != 0 and err.strip():
            raise RuntimeError(f"Sudo command failed (code {exit_status}): {err}")
        return out

    def run_privileged(self, command: str, justification: str = "Administrative operation") -> str:
        """Runs command as root directly if connected as root, otherwise escalates via sudo."""
        if self.user == "root":
            return self.run_cmd(command)
        return self.run_sudo_cmd(command, justification)

    def run_with_sudo_fallback(self, command: str, justification: str = "Operation requiring elevated privileges") -> str:
        """Attempts normal execution first; if permission denied occurs, automatically escalates to sudo."""
        if self.user == "root":
            return self.run_cmd(command)
        
        out = self.run_cmd(command)
        if "permission denied" in out.lower() or "operation not permitted" in out.lower():
            return self.run_sudo_cmd(command, justification)
        return out
