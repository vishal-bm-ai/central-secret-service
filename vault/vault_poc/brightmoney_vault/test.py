from interface import VaultInterface
i = VaultInterface()
creds=i._read_secret_from_path("database/static-creds/demo")
print(creds["data"])