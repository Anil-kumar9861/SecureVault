from securevault.vault.service import WeakPasswordError, validate_master_password

passwords = [
    "SecureVault2026!",
    "hello",
    "aaaaaaaaaaaa",
    "          ",
]

for password in passwords:
    try:
        validate_master_password(password)
        print(password, "-> Valid")
    except WeakPasswordError as exc:
        print(repr(password), "->", exc)
