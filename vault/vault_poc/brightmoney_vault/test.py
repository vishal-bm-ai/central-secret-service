from interface import VaultInterface
from decouple import config
i = VaultInterface()
creds=i._read_secret_from_path(config("SECRET_PATH"))
print(creds)