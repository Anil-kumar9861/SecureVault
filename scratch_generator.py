from securevault.vault.generator import generate_password

password = generate_password(20)

print("Generated password:", password)
print("Length:", len(password))
