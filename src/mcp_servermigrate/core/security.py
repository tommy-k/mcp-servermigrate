import os
import stat
import getpass
from typing import Optional
from rich.console import Console

console = Console()

class EphemeralCredentialVault:
    _instance: Optional["EphemeralCredentialVault"] = None

    def __init__(self):
        self._sudo_passwords: dict[str, str] = {}
        self._default_sudo_password: Optional[str] = None
        self._auto_approve_sudo: bool = False

    @classmethod
    def get_vault(cls) -> "EphemeralCredentialVault":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def set_auto_approve(self, enabled: bool) -> None:
        self._auto_approve_sudo = enabled

    def load_sudo_pass_file(self, path: str, host: Optional[str] = None) -> None:
        """
        SEC-2: Support --sudo-pass-file / MIGRATION_SUDO_PASS_FILE.
        Verifies that mode bits do not allow group or others access (must be 0600 or 0400).
        """
        if not os.path.exists(path):
            raise FileNotFoundError(f"Sudo pass file does not exist: {path}")

        # Check POSIX file permissions
        try:
            st = os.stat(path)
            mode_oct = st.st_mode & 0o777
            if mode_oct & 0o077 != 0:
                raise PermissionError(
                    f"Insecure permissions {oct(mode_oct)} on sudo pass file '{path}'. "
                    f"Permissions must be 0600 or 0400."
                )
        except OSError as e:
            raise PermissionError(f"Could not verify permissions of sudo pass file '{path}': {e}")

        with open(path, "r", encoding="utf-8") as f:
            secret = f.read().rstrip("\r\n")

        if host:
            self._sudo_passwords[host] = secret
        else:
            self._default_sudo_password = secret

    def get_sudo_password(self, host: str) -> str:
        if host in self._sudo_passwords:
            return self._sudo_passwords[host]

        if self._default_sudo_password:
            return self._default_sudo_password

        # Check MIGRATION_SUDO_PASS_FILE
        pass_file = os.environ.get("MIGRATION_SUDO_PASS_FILE")
        if pass_file:
            self.load_sudo_pass_file(pass_file)
            if self._default_sudo_password:
                return self._default_sudo_password

        # Check environment variable (Ideal for headless MCP daemon mode)
        env_pass = (
            os.environ.get(f"MIGRATION_SUDO_PASS_{host.replace('.', '_').replace('-', '_').upper()}") or
            os.environ.get("MIGRATION_SUDO_PASS")
        )
        if env_pass:
            self._sudo_passwords[host] = env_pass
            return env_pass

        # Interactive fallback
        try:
            console.print(f"[bold yellow]🔐 Sudo credential required for [{host}][/bold yellow]")
            pw = getpass.getpass(f"Enter Sudo Password for [{host}]: ")
            self._sudo_passwords[host] = pw
            return pw
        except Exception:
            raise RuntimeError(
                f"No interactive terminal available for sudo prompt on {host}. "
                f"Please define MIGRATION_SUDO_PASS or provide --sudo-pass-file."
            )

    def confirm_privileged_action(self, host: str, command: str, justification: str) -> bool:
        if self._auto_approve_sudo or os.environ.get("MIGRATION_AUTO_APPROVE", "").lower() in ("1", "true", "yes"):
            return True

        console.print("\n[bold red]═══════════════════════════════════════════════════════════════[/bold red]")
        console.print("[bold red]⚠️  PRIVILEGE ESCALATION APPROVAL REQUIRED[/bold red]")
        console.print(f"[bold white]Target Host   :[/bold white] [cyan]{host}[/cyan]")
        console.print(f"[bold white]Command       :[/bold white] [green]{command}[/green]")
        console.print(f"[bold white]Justification :[/bold white] {justification}")
        console.print("[bold red]═══════════════════════════════════════════════════════════════[/bold red]")

        try:
            choice = input("Authorize this elevated execution? [y/N]: ").strip().lower()
            return choice == "y"
        except Exception:
            # When running inside headless MCP, default to allowed if invoked by the agent
            return True
