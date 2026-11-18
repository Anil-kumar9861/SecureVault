import math
import secrets
import string


def generate_password(length: int = 20) -> str:
    if length < 12:
        raise ValueError("Password length must be at least 12")

    characters = (
        string.ascii_lowercase
        + string.ascii_uppercase
        + string.digits
        + string.punctuation
    )

    password = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
        secrets.choice(string.punctuation),
    ]

    for _ in range(length - 4):
        password.append(secrets.choice(characters))

    secrets.SystemRandom().shuffle(password)

    return "".join(password)


def calculate_strength(password: str) -> str:
    """Estimate password strength based on length and character variety."""

    if not password:
        return "Weak"

    pool_size = 0

    if any(char.islower() for char in password):
        pool_size += 26

    if any(char.isupper() for char in password):
        pool_size += 26

    if any(char.isdigit() for char in password):
        pool_size += 10

    if any(not char.isalnum() for char in password):
        pool_size += 32

    entropy = len(password) * math.log2(pool_size) if pool_size else 0

    if entropy < 60:
        return "Weak"
    elif entropy < 80:
        return "Medium"
    elif entropy < 100:
        return "Strong"
    else:
        return "Very Strong"
