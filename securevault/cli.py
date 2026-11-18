import csv
import msvcrt
from datetime import date
from functools import wraps
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from securevault.exceptions import (
    AmbiguousCredentialError,
    VaultAlreadyExistsError,
    VaultError,
    VaultNotInitializedError,
    WeakPasswordError,
    WrongMasterPasswordError,
)
from securevault.storage import Storage
from securevault.vault.backup import (
    create_backup,
    load_backup,
    read_backup,
    save_backup,
)
from securevault.vault.credentials import CredentialManager
from securevault.vault.generator import calculate_strength, generate_password
from securevault.vault.service import Vault, validate_master_password

console = Console()
error_console = Console(stderr=True)

app = typer.Typer(help="SecureVault - encrypted password manager")
vault_app = typer.Typer(help="Manage your password vault")
VALID_HISTORY_EVENTS = {
    "vault_created",
    "credential_added",
    "credential_updated",
    "credential_deleted",
    "credentials_imported",
    "master_password_changed",
    "unlock_failed",
    "backup_exported",
    "backup_imported",
}
app.add_typer(vault_app, name="vault")


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------


def safe_text(value, style=None) -> Text:
    """Display dynamic data without interpreting Rich markup."""
    return Text(str(value if value is not None else ""), style=style)


def success(message: str) -> None:
    console.print(safe_text(message, "green"))


def warn(message: str) -> None:
    console.print(safe_text(message, "yellow"))


def fail(message: str) -> None:
    error_console.print(safe_text(f"Error: {message}", "red"))


def export_history_csv(events: list[dict], file_path: str) -> None:
    """Export audit history to a CSV file."""

    path = Path(file_path)

    if path.exists():
        raise FileExistsError(f"File already exists: {path}")
    if not path.parent.exists():
        raise FileNotFoundError(f"Destination folder does not exist: {path.parent}")

    with path.open("w", newline="", encoding="utf-8-sig") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=["id", "at", "event", "detail"],
        )

        writer.writeheader()
        writer.writerows(events)


def info_line(label: str, value) -> None:
    console.print(safe_text(f"{label}: {value}"))


def accounts_table(rows: list[dict], title: Optional[str] = None) -> Table:
    """Create a consistent table for credential listings and search results."""

    table = Table(
        title=Text(title, style="bold #D98268") if title else None,
        title_justify="center",
        header_style="bold #D98268",
        border_style="#D98268",
        show_lines=True,
        expand=True,
    )

    table.add_column("ID", style="dim", justify="center", width=6)
    table.add_column("Service")
    table.add_column("Label")
    table.add_column("Username")

    for item in rows:
        table.add_row(
            safe_text(item.get("id")),
            safe_text(item.get("service")),
            safe_text(item.get("label")),
            safe_text(item.get("username")),
        )

    return table


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------


def print_banner() -> None:
    content = Table.grid(expand=True, padding=(0, 2))

    content.add_column(ratio=1)
    content.add_column(ratio=1)

    content.add_row(
        "[bold white]Welcome back![/bold white]\n\n"
        "[dim]Your personal encrypted[/dim]\n"
        "[dim]password manager.[/dim]",
        "[bold #D98268]QUICK COMMANDS[/bold #D98268]\n\n"
        "[white]sv vault list[/white]\n"
        "[white]sv vault add github[/white]\n"
        "[white]sv vault search git[/white]",
    )

    console.print()

    console.print(
        Panel(
            content,
            title="[bold #D98268]SECUREVAULT[/bold #D98268]",
            subtitle="[dim]Secure • Private • Reliable[/dim]",
            border_style="#DBDADA",
            padding=(1, 2),
        )
    )

    console.print("[dim]  VERSION 1.0[/dim]")
    console.print()


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context) -> None:
    """SecureVault command-line application."""

    if ctx.invoked_subcommand is None:
        print_banner()
        console.print(ctx.get_help(), markup=False, highlight=False)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def prompt_password_with_strength(prompt: str) -> str:
    """Prompt for a hidden password and display its live strength."""

    password_chars = []

    strength_colors = {
        "Weak": "red",
        "Medium": "yellow",
        "Strong": "green",
        "Very Strong": "cyan",
    }

    def get_display() -> Text:
        password = "".join(password_chars)

        output = Text()
        output.append(f"{prompt}: ", style="bold")
        output.append("•" * len(password_chars), style="white")

        if password:
            strength = calculate_strength(password)
            output.append("   ")

            output.append(
                f"Strength: {strength}",
                style=f"bold {strength_colors[strength]}",
            )

        return output

    console.print()

    with Live(
        get_display(),
        console=console,
        refresh_per_second=10,
        transient=False,
    ) as live:
        while True:
            char = msvcrt.getwch()

            if char in ("\r", "\n"):
                break

            if char == "\003":
                raise KeyboardInterrupt

            if char in ("\b", "\x7f"):
                if password_chars:
                    password_chars.pop()

            elif char in ("\x00", "\xe0"):
                # Ignore special keys such as arrows and function keys.
                msvcrt.getwch()

            else:
                password_chars.append(char)

            live.update(get_display())

    console.print()

    return "".join(password_chars)


def handle_errors(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)

        except AmbiguousCredentialError as exc:
            fail(str(exc))
            error_console.print(accounts_table(exc.matches, "Matching Credentials"))
            raise typer.Exit(code=1)

        except VaultError as exc:
            fail(str(exc))
            raise typer.Exit(code=1)

        except (OSError, ValueError) as exc:
            fail(str(exc))
            raise typer.Exit(code=1)

    return wrapper


def open_manager(prompt: str = "Master password") -> CredentialManager:
    storage = Storage()

    # Check whether the vault exists before asking for a password.
    meta = storage.load_vault_meta()

    master_password = typer.prompt(
        prompt,
        hide_input=True,
    )

    try:
        vault = Vault.unlock(meta, master_password)

    except WrongMasterPasswordError:
        storage.log_event("unlock_failed")
        raise

    return CredentialManager(storage, vault)


def prompt_backup_password(confirm: bool) -> str:
    """Ask for a backup password and validate new backup passwords."""

    password = typer.prompt(
        "Backup password",
        hide_input=True,
        confirmation_prompt=confirm,
    )

    if confirm:
        try:
            validate_master_password(password)

        except WeakPasswordError as exc:
            raise WeakPasswordError(
                str(exc).replace("Master password", "Backup password")
            ) from exc

    return password


def load_backup_file(file_path: str) -> list[dict]:
    """Read and decrypt a backup without importing it."""

    try:
        backup_data = read_backup(file_path)

        backup_password = prompt_backup_password(confirm=False)

        return load_backup(backup_data, backup_password)

    except (OSError, ValueError) as exc:
        raise VaultError(str(exc)) from exc


def copy_to_clipboard(value: str) -> None:
    """Copy a password while handling unavailable clipboard support."""

    try:
        import pyperclip

        pyperclip.copy(value)

    except ImportError as exc:
        raise VaultError("Clipboard support requires the pyperclip package") from exc

    except pyperclip.PyperclipException as exc:
        raise VaultError("Clipboard is not available on this system") from exc


# ---------------------------------------------------------------------------
# Vault commands
# ---------------------------------------------------------------------------


@vault_app.command("init")
@handle_errors
def init_vault() -> None:
    """Initialize a new password vault."""

    storage = Storage()
    storage.init_schema()

    try:
        storage.load_vault_meta()

    except VaultNotInitializedError:
        pass

    else:
        raise VaultAlreadyExistsError("Vault already exists")

    master_password = prompt_password_with_strength("Create master password")

    validate_master_password(master_password)

    confirm_password = typer.prompt(
        "Confirm master password",
        hide_input=True,
    )

    if master_password != confirm_password:
        raise VaultError("Master passwords do not match")

    vault = Vault.create(master_password)

    storage.save_vault_meta(vault.export_meta())

    success("Vault created successfully!")


@vault_app.command("add")
@handle_errors
def add_credential(
    service: str,
    label: str = typer.Option("", "--label", "-l"),
    username: Optional[str] = typer.Option(None, "--username", "-u"),
    url: str = typer.Option("", "--url"),
    notes: str = typer.Option("", "--notes"),
) -> None:
    """Add a new encrypted credential."""

    manager = open_manager()

    if username is None:
        username = typer.prompt("Username")

    password = prompt_password_with_strength("Create credential password")

    confirm_password = typer.prompt(
        "Confirm credential password",
        hide_input=True,
    )

    if password != confirm_password:
        raise VaultError("Passwords do not match")

    cred_id = manager.add(
        service=service,
        username=username,
        password=password,
        label=label,
        url=url,
        notes=notes,
    )

    success(f"Added credential {cred_id} ({service.strip()})")


@vault_app.command("list")
@handle_errors
def list_credentials() -> None:
    """List all saved credentials."""

    credentials = open_manager().list_all()

    if not credentials:
        warn("No credentials found.")
        return

    console.print(accounts_table(credentials, "Saved Credentials"))


@vault_app.command("search")
@handle_errors
def search_credentials(text: str) -> None:
    """Search credentials by service or label."""

    credentials = open_manager().search(text)

    if not credentials:
        warn("No matches found.")
        return

    console.print(accounts_table(credentials, f"Search Results: {text}"))


@vault_app.command("get")
@handle_errors
def get_credential(
    identifier: str,
    show: bool = typer.Option(
        False,
        "--show",
        help="Display the actual password.",
    ),
    copy: bool = typer.Option(
        False,
        "--copy",
        help="Copy the password to the clipboard.",
    ),
) -> None:
    """Retrieve a credential by service name or ID."""

    manager = open_manager()

    credential = manager.get(manager.resolve(identifier))

    if copy:
        copy_to_clipboard(credential["password"])

        success("Password copied to clipboard.")
        warn("The clipboard is not cleared automatically. Clear it when done.")

    password = credential["password"] if show else "********"

    info_line("ID", credential["id"])
    info_line("Service", credential["service"])
    info_line("Label", credential["label"])
    info_line("Username", credential["username"])
    info_line("Password", password)
    info_line("URL", credential["url"])
    info_line("Notes", credential["notes"])


@vault_app.command("edit")
@handle_errors
def edit_credential(
    identifier: str,
    service: Optional[str] = typer.Option(None, "--service"),
    label: Optional[str] = typer.Option(None, "--label", "-l"),
    username: Optional[str] = typer.Option(None, "--username", "-u"),
    url: Optional[str] = typer.Option(None, "--url"),
    notes: Optional[str] = typer.Option(None, "--notes"),
    change_password: bool = typer.Option(
        False,
        "--change-password",
    ),
) -> None:
    """Edit an existing credential."""

    options = {
        "service": service,
        "label": label,
        "username": username,
        "url": url,
        "notes": notes,
    }

    changes = {name: value for name, value in options.items() if value is not None}

    if not changes and not change_password:
        raise VaultError("Nothing to change")

    manager = open_manager()

    cred_id = manager.resolve(identifier)

    if change_password:
        changes["password"] = typer.prompt(
            "New password",
            hide_input=True,
            confirmation_prompt=True,
        )

    manager.edit(cred_id, **changes)

    success(f"Updated credential {cred_id}")


@vault_app.command("delete")
@handle_errors
def delete_credential(
    identifier: str,
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Skip deletion confirmation.",
    ),
) -> None:
    """Delete a saved credential."""

    manager = open_manager()

    cred_id = manager.resolve(identifier)

    if not yes:
        typer.confirm(
            f"Are you sure you want to delete credential {cred_id}?",
            abort=True,
        )

    manager.delete(cred_id)

    success(f"Deleted credential {cred_id}")


@vault_app.command("generate")
@handle_errors
def generate(
    length: int = typer.Option(
        20,
        "--length",
        min=12,
        max=128,
        help="Length of the generated password",
    ),
) -> None:
    """Generate a secure random password."""

    password = generate_password(length)

    strength = calculate_strength(password)

    output = Text("Generated password: ", style="green")
    output.append(password, style="bold white")

    console.print(output)

    strength_colors = {
        "Weak": "red",
        "Medium": "yellow",
        "Strong": "green",
        "Very Strong": "cyan",
    }

    strength_output = Text("Password strength: ")
    strength_output.append(strength, style=f"bold {strength_colors[strength]}")

    console.print(strength_output)


@vault_app.command("change-master")
@handle_errors
def change_master() -> None:
    """Change the vault master password."""

    manager = open_manager("Current master password")

    new_password = typer.prompt(
        "New master password",
        hide_input=True,
        confirmation_prompt=True,
    )

    manager.change_master_password(new_password)

    success("Master password changed successfully.")


# ---------------------------------------------------------------------------
# Backup commands
# ---------------------------------------------------------------------------


@vault_app.command("export")
@handle_errors
def export_backup(file_path: str) -> None:
    """Export all credentials into an encrypted JSON backup."""

    manager = open_manager()

    saved_credentials = manager.list_all()

    if not saved_credentials:
        warn("No credentials found to export.")
        return

    backup_password = prompt_backup_password(confirm=True)

    credentials = []

    for item in saved_credentials:
        credential = manager.get(item["id"])

        for field in ("created_at", "updated_at"):
            if credential.get(field) is not None:
                credential[field] = credential[field].isoformat()

        credentials.append(credential)

    backup_data = create_backup(
        credentials,
        backup_password,
    )

    try:
        save_backup(file_path, backup_data)

    except FileExistsError:
        if not typer.confirm("Backup already exists. Overwrite it?"):
            warn("Export cancelled.")
            return

        save_backup(
            file_path,
            backup_data,
            overwrite=True,
        )

    # Log the export without recording any credential contents.
    Storage().log_event(
        "backup_exported",
        f"count={len(credentials)}",
    )

    success(f"Successfully exported {len(credentials)} credentials to {file_path}")


@vault_app.command("preview")
@handle_errors
def preview_backup(
    file_path: str,
    show_passwords: bool = typer.Option(
        False,
        "--show-passwords",
        help="Display actual passwords.",
    ),
) -> None:
    """Preview an encrypted backup without importing it."""

    credentials = load_backup_file(file_path)

    if not credentials:
        warn("No credentials found in backup.")
        return

    table = Table(
        title=Text("Backup Preview", style="bold #D98268"),
        border_style="#385A83",
        show_lines=True,
    )

    for column in (
        "ID",
        "Service",
        "Label",
        "Username",
        "Password",
        "URL",
        "Notes",
    ):
        table.add_column(column)

    for item in credentials:
        password = str(item.get("password", "")) if show_passwords else "********"

        table.add_row(
            safe_text(item.get("id")),
            safe_text(item.get("service")),
            safe_text(item.get("label")),
            safe_text(item.get("username")),
            safe_text(password),
            safe_text(item.get("url")),
            safe_text(item.get("notes")),
        )

    console.print(table)

    success(f"Found {len(credentials)} credentials. No database changes were made.")


@vault_app.command("import")
@handle_errors
def import_backup(file_path: str) -> None:
    """Import credentials from an encrypted JSON backup."""

    manager = open_manager()

    credentials = load_backup_file(file_path)

    if not credentials:
        warn("No credentials found in backup.")
        return

    console.print(f"\nBackup contains {len(credentials)} credentials.")

    if not typer.confirm("Continue with import?"):
        warn("Import cancelled.")
        return

    result = manager.import_backup_credentials(credentials)

    # The storage transaction already logs credentials_imported.
    # This event records the overall backup operation.
    Storage().log_event(
        "backup_imported",
        f"imported={result['imported']} skipped={result['skipped']}",
    )

    console.print("\nImport Summary", style="bold")
    console.print(f"Imported: {result['imported']}")
    console.print(f"Skipped: {result['skipped']}")

    success("Import completed.")


@vault_app.command("history")
@handle_errors
def show_history(
    limit: int = typer.Option(
        50,
        "--limit",
        min=1,
        help="Maximum number of audit events to display.",
    ),
    event: Optional[str] = typer.Option(
        None,
        "--event",
        help="Filter history by event type.",
    ),
    export: Optional[str] = typer.Option(
        None,
        "--export",
        help="Export audit history to a CSV file.",
    ),
    no_display: bool = typer.Option(
        False,
        "--no-display",
        help="Export history without displaying it in the terminal.",
    ),
    since: Optional[date] = typer.Option(
        None,
        "--since",
        help="Show events from this date onward (YYYY-MM-DD).",
    ),
    until: Optional[date] = typer.Option(
        None,
        "--until",
        help="Show events up to this date (YYYY-MM-DD).",
    ),
) -> None:
    """Display SecureVault audit history."""

    if event is not None and event not in VALID_HISTORY_EVENTS:
        fail(
            f"Invalid event type: {event}. "
            f"Available events: {', '.join(sorted(VALID_HISTORY_EVENTS))}"
        )
        return

    # Authenticate the user before accessing audit history.
    open_manager("Enter master password to access audit history")

    events = Storage().list_events(
        limit=limit,
        event=event,
        since=since,
        until=until,
    )

    if not events:
        warn("No audit history found.")
        return

    if export:
        export_history_csv(events, export)
        success(f"Audit history exported to: {export}")

    if no_display:
        return

    table = Table(
        title=Text("Audit History", style="bold #D98268"),
        header_style="bold #D98268",
        border_style="#D98268",
        show_lines=True,
        expand=True,
    )

    table.add_column("ID", justify="center", width=6)
    table.add_column("Date")
    table.add_column("Event")
    table.add_column("Details")

    for event in events:
        table.add_row(
            safe_text(event["id"]),
            safe_text(event["at"]),
            safe_text(event["event"]),
            safe_text(event["detail"]),
        )

    console.print(table)
    info_line("Events displayed", len(events))


if __name__ == "__main__":
    app()
