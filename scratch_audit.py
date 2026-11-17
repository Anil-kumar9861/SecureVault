import os

# IMPORTANT: Use the test database, never the real database.
os.environ["DB_NAME"] = "securevault_test"

from typer.testing import CliRunner

from securevault.cli import app
from securevault.storage import Storage

assert os.environ["DB_NAME"].endswith("_test")

runner = CliRunner()
db = Storage("securevault_test")

# Reset only the test database.
db.reset_schema()

MASTER = "correct horse battery"


def run(args, *typed):
    """Run a CLI command and provide answers to prompts."""
    return runner.invoke(
        app,
        args,
        input="\n".join(typed) + "\n",
    )


def check(result, *needles, absent=(), expected_exit_code=0):
    """Check command exit code and expected output."""
    assert result.exit_code == expected_exit_code, (
        f"Expected exit code {expected_exit_code}, "
        f"got {result.exit_code}:\n{result.output}"
    )

    for needle in needles:
        assert needle in result.output, (
            f"Expected {needle!r} in output:\n{result.output}"
        )

    for needle in absent:
        assert needle not in result.output, (
            f"Unexpected {needle!r} in output:\n{result.output}"
        )

    print(f"PASS (exit code: {result.exit_code})")


print("\n--- INITIALIZATION ---")

check(
    run(["vault", "init"], "short", "short"),
    expected_exit_code=1,
)

check(
    run(["vault", "list"], MASTER),
    "not initialized",
    expected_exit_code=1,
)

check(
    run(["vault", "init"], MASTER, MASTER),
    "Vault created",
)

check(
    run(["vault", "init"], MASTER, MASTER),
    "Vault already exists",
    expected_exit_code=1,
)


print("\n--- ADD ---")

check(
    run(
        ["vault", "add", "github", "-u", "ravi", "-l", "personal"],
        MASTER,
        "s3cret!",
        "s3cret!",
    ),
    "Added credential 1",
)

check(
    run(
        ["vault", "add", "github", "-u", "work-user", "-l", "work"],
        MASTER,
        "pw2",
        "pw2",
    ),
    "Added credential 2",
)

check(
    run(
        ["vault", "add", "Gmail"],
        MASTER,
        "me@mail.com",
        "pw3",
        "pw3",
    ),
    "Added credential 3",
)

check(
    run(
        ["vault", "add", "   "],
        MASTER,
        "u",
        "pw",
        "pw",
    ),
    "Service cannot be empty",
    expected_exit_code=1,
)

check(
    run(["vault", "add", "x", "--password", "abc"]),
    "No such option",
    expected_exit_code=2,
)


print("\n--- LIST AND SEARCH ---")

check(
    run(["vault", "list"], MASTER),
    "github",
    "personal",
    "ravi",
    "work-user",
    "Gmail",
    "me@mail.com",
    absent=("s3cret!", "pw2", "pw3"),
)

check(
    run(["vault", "search", "GIT"], MASTER),
    "github",
    absent=("Gmail",),
)

check(
    run(["vault", "search", "zzz"], MASTER),
    "No matches found",
)


print("\n--- GET ---")

check(
    run(["vault", "get", "1"], MASTER),
    "Username: ravi",
    "Password: ********",
    absent=("s3cret!",),
)

check(
    run(["vault", "get", "1", "--show"], MASTER),
    "Password: s3cret!",
)

check(
    run(["vault", "get", "gmail"], MASTER),
    "me@mail.com",
)

check(
    run(["vault", "get", "github"], MASTER),
    "Several accounts",
    "personal",
    "work-user",
    absent=("s3cret!",),
    expected_exit_code=1,
)

check(
    run(["vault", "get", "99"], MASTER),
    "Credential 99 not found",
    expected_exit_code=1,
)

check(
    run(["vault", "get", "nothing"], MASTER),
    "No credential named nothing",
    expected_exit_code=1,
)

check(
    run(["vault", "get", "1"], "wrong password!!"),
    "Wrong master password",
    expected_exit_code=1,
)


print("\n--- EDIT ---")

check(
    run(["vault", "edit", "1", "--username", "ravi2"], MASTER),
    "Updated credential 1",
)

check(
    run(["vault", "get", "1"], MASTER),
    "Username: ravi2",
)

check(
    run(
        ["vault", "edit", "1", "--change-password"],
        MASTER,
        "newpw",
        "newpw",
    ),
    "Updated credential 1",
)

check(
    run(["vault", "get", "1", "--show"], MASTER),
    "Password: newpw",
)

check(
    run(["vault", "edit", "1"], MASTER),
    "Nothing to change",
    expected_exit_code=1,
)

check(
    run(["vault", "edit", "1", "--service", " "], MASTER),
    "Service cannot be empty",
    expected_exit_code=1,
)

check(
    run(["vault", "edit", "99", "--label", "x"], MASTER),
    "Credential 99 not found",
    expected_exit_code=1,
)


print("\n--- DELETE ---")

# Cancel deletion.
check(
    run(["vault", "delete", "2"], MASTER, "n"),
    "Aborted",
    expected_exit_code=1,
)

assert len(db.list_credentials()) == 3
print("PASS: Cancelled deletion preserves credential")

# Confirm deletion without an interactive prompt.
check(
    run(["vault", "delete", "2", "--yes"], MASTER),
    "Deleted credential 2",
)

assert len(db.list_credentials()) == 2
print("PASS: Confirmed deletion removes credential")


print("\n--- SECURITY ---")

credentials = str(db.list_credentials())

assert "s3cret!" not in credentials
assert "newpw" not in credentials

print("PASS: Passwords are not exposed in credential listings")

events = db.list_events()

assert not any(
    "s3cret" in event["detail"] or "pw" in event["detail"] for event in events
)

print("PASS: Passwords are not exposed in audit details")

assert any(event["event"] == "unlock_failed" for event in events)
assert any(event["event"] == "credential_added" for event in events)
assert any(event["event"] == "credential_updated" for event in events)
assert any(event["event"] == "credential_deleted" for event in events)

print("PASS: Audit events recorded")


print("\n--- HELP ---")

check(
    run(["--help"]),
    "vault",
)

check(
    run(["vault", "--help"]),
    "init",
    "add",
    "list",
    "search",
    "get",
    "edit",
    "delete",
)


print("\n================================")
print("ALL CLI TESTS PASSED SUCCESSFULLY")
print("================================")
