import os

os.environ["DB_NAME"] = "securevault_test"

from typer.testing import CliRunner

from securevault.cli import app
from securevault.storage import Storage

assert os.environ["DB_NAME"].endswith("_test")
runner = CliRunner()
Storage("securevault_test").reset_schema()
M = "correct horse battery"


def run(args, *typed):
    return runner.invoke(app, args, input="\n".join(typed) + "\n")


run(["vault", "init"], M, M)

r = run(["vault", "add", "br", "-u", "[red]x", "-l", "[b]"], M, "pa[/x]ss", "pa[/x]ss")
print(r.exit_code)

r = run(["vault", "get", "1", "--show"], M)
print(r.exit_code, "Password: pa[/x]ss" in r.output, "Username: [red]x" in r.output)

r = run(["vault", "list"], M)
print(r.exit_code, "[red]x" in r.output, "[b]" in r.output)

r = run(["vault", "get", "nobody[x]"], M)
print(r.exit_code, "nobody[x]" in r.output)
