from functools import wraps

import typer
from rich.console import Console
from rich.table import Table

from securevault.exceptions import (
    AmbiguousCredentialError,
    VaultAlreadyExistsError,
    VaultError,
    VaultNotInitializedError,
    WrongMasterPasswordError,
)
from securevault.storage import Storage
from securevault.vault.credentials import CredentialManager
from securevault.vault.service import Vault

console = Console()
error_console = Console(stderr=True)

app = typer.Typer(help="SecureVault - encrypted password manager")

vault_app = typer.Typer(help="Manage your password vault")

app.add_typer(vault_app, name="vault")


def handle_errors(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)

        except AmbiguousCredentialError as exc:
            error_console.print(f"[red]{exc}[/red]")

            table = Table(
                title="Matching Credentials",
                show_header=True,
            )

            table.add_column("ID")
            table.add_column("Service")
            table.add_column("Label")
            table.add_column("Username")

            for item in exc.matches:
                table.add_row(
                    str(item["id"]),
                    item["service"],
                    item["label"],
                    item["username"],
                )

            error_console.print(table)
            raise typer.Exit(code=1)

        except VaultError as exc:
            error_console.print(f"[red]Error: {exc}[/red]")
            raise typer.Exit(code=1)

    return wrapper


def open_manager():
    storage = Storage()

    # Check whether the vault exists before asking for a password.
    meta = storage.load_vault_meta()

    # Ask for the master password without displaying it.
    master_password = typer.prompt(
        "Master password",
        hide_input=True,
    )

    try:
        vault = Vault.unlock(meta, master_password)

    except WrongMasterPasswordError:
        storage.log_event("unlock_failed")
        raise

    return CredentialManager(storage, vault)


@vault_app.command("init")
@handle_errors
def init_vault():
    """Initialize a new password vault."""

    storage = Storage()

    # Create database tables.
    storage.init_schema()

    # Check whether a vault already exists.
    try:
        storage.load_vault_meta()

    except VaultNotInitializedError:
        pass

    else:
        raise VaultAlreadyExistsError("Vault already exists")

    # Ask for the master password twice.
    master_password = typer.prompt(
        "Create master password",
        hide_input=True,
        confirmation_prompt=True,
    )

    # Create the vault.
    vault = Vault.create(master_password)

    # Save metadata.
    storage.save_vault_meta(vault.export_meta())

    console.print("[green]Vault created successfully![/green]")


@vault_app.command("add")
@handle_errors
def add_credential(
    service: str,
    label: str = typer.Option("", "--label", "-l"),
    username: str = typer.Option(None, "--username", "-u"),
    url: str = typer.Option("", "--url"),
    notes: str = typer.Option("", "--notes"),
):
    """Add a new encrypted credential."""

    # Unlock the vault.
    manager = open_manager()

    # Ask for username if it wasn't supplied through an option.
    if username is None:
        username = typer.prompt("Username")

    # Ask for password securely.
    password = typer.prompt(
        "Password",
        hide_input=True,
        confirmation_prompt=True,
    )

    # Save the encrypted credential.
    cred_id = manager.add(
        service=service,
        username=username,
        password=password,
        label=label,
        url=url,
        notes=notes,
    )

    console.print(f"[green]Added credential {cred_id} ({service})[/green]")


@vault_app.command("list")
@handle_errors
def list_credentials():
    """List all saved credentials."""

    manager = open_manager()

    credentials = manager.list_all()

    if not credentials:
        console.print("[yellow]No credentials found.[/yellow]")
        return

    table = Table(title="Saved Credentials")

    table.add_column("ID")
    table.add_column("Service")
    table.add_column("Label")
    table.add_column("Username")

    for item in credentials:
        table.add_row(
            str(item["id"]),
            item["service"],
            item["label"],
            item["username"],
        )

    console.print(table)


@vault_app.command("search")
@handle_errors
def search_credentials(text: str):
    """Search credentials by service or label."""

    manager = open_manager()

    credentials = manager.search(text)

    if not credentials:
        console.print("[yellow]No matches found.[/yellow]")
        return

    table = Table(title=f"Search Results: {text}")

    table.add_column("ID")
    table.add_column("Service")
    table.add_column("Label")
    table.add_column("Username")

    for item in credentials:
        table.add_row(
            str(item["id"]),
            item["service"],
            item["label"],
            item["username"],
        )

    console.print(table)


@vault_app.command("get")
@handle_errors
def get_credential(
    identifier: str,
    show: bool = typer.Option(
        False,
        "--show",
        help="Display the actual password.",
    ),
):
    """Retrieve a credential by service name or ID."""

    manager = open_manager()

    cred_id = manager.resolve(identifier)

    credential = manager.get(cred_id)

    password = credential["password"] if show else "********"

    console.print(f"ID: {credential['id']}")
    console.print(f"Service: {credential['service']}")
    console.print(f"Label: {credential['label']}")
    console.print(f"Username: {credential['username']}")
    console.print(f"Password: {password}")
    console.print(f"URL: {credential['url']}")
    console.print(f"Notes: {credential['notes']}")


@vault_app.command("edit")
@handle_errors
def edit_credential(
    identifier: str,
    service: str = typer.Option(None, "--service"),
    label: str = typer.Option(None, "--label", "-l"),
    username: str = typer.Option(None, "--username", "-u"),
    url: str = typer.Option(None, "--url"),
    notes: str = typer.Option(None, "--notes"),
    change_password: bool = typer.Option(
        False,
        "--change-password",
    ),
):
    """Edit an existing credential."""

    changes = {}

    if service is not None:
        changes["service"] = service

    if label is not None:
        changes["label"] = label

    if username is not None:
        changes["username"] = username

    if url is not None:
        changes["url"] = url

    if notes is not None:
        changes["notes"] = notes

    # Check whether the user requested any changes.
    if not changes and not change_password:
        raise VaultError("Nothing to change")

    # Unlock the vault.
    manager = open_manager()

    # Find the credential.
    cred_id = manager.resolve(identifier)

    # Ask for a new password if requested.
    if change_password:
        changes["password"] = typer.prompt(
            "New password",
            hide_input=True,
            confirmation_prompt=True,
        )

    # Save changes.
    manager.edit(cred_id, **changes)

    console.print(f"[green]Updated credential {cred_id}[/green]")


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
):
    """Delete a saved credential."""

    # Unlock the vault.
    manager = open_manager()

    # Find the credential.
    cred_id = manager.resolve(identifier)

    # Ask for confirmation unless --yes is provided.
    if not yes:
        typer.confirm(
            f"Are you sure you want to delete credential {cred_id}?",
            abort=True,
        )

    # Delete the credential.
    manager.delete(cred_id)

    console.print(f"[green]Deleted credential {cred_id}[/green]")


if __name__ == "__main__":
    app()
