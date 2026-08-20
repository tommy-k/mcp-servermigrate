import getpass
from typing import Optional
from rich.console import Console

console = Console()

class EphemeralCredentialVault:
    _instance: Optional["EphemeralCredentialVault"] = None

    def __init__(self):
        self._sudo_passwords: dict[str, str] = {}
        self._auto_approve_sudo: bool = False

    @classmethod
    def get_vault(cls) -> "EphemeralCredentialVault":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def set_auto_approve(self, enabled: bool) -> None:
        self._auto_approve_sudo = enabled

    def get_sudo_password(self, host: str) -> str:
        if host not in self._sudo_passwords:
            console.print(f"[bold yellow]🔐 Sudo credential required for [{host}][/bold yellow]")
            self._sudo_passwords[host] = getpass.getpass(f"Enter Sudo Password for [{host}]: ")
        return self._sudo_passwords[host]

    def confirm_privileged_action(self, host: str, command: str, justification: str) -> bool:
        if self._auto_approve_sudo:
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
        except (KeyboardInterrupt, EOFError):
            return False
