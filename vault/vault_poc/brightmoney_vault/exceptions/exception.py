
class UnauthenticatedClientException(Exception):

    def __str__(self):
        return "Unable to authenticate Vault client using provided credentials"

class UnsupportedAuthMethodException(Exception):

    def __str__(self):
        return "Unsupported auth method"