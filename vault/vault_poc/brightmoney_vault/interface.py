
import hvac
import requests
from auth import get_authenticated_client

class VaultInterface():
    
    def __init__(self):
        self._hvac = None

    def _get_hvac_client(self):
        self._hvac = get_authenticated_client()
        return self._hvac
    
    def _read_secret_from_path(self, secret_path):
        client = self._get_hvac_client()
        creds = None
        response = client.read(secret_path)
        creds = response.get("data")
        return creds


