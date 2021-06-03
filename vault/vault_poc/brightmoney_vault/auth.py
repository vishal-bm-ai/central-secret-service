import hvac
import requests
import os
from decouple import config
from exceptions.exception import UnauthenticatedClientException, UnsupportedAuthMethodException

class VaultAuthenticator:
    """
    Use one of the factory methods (`app_id`, `token`, `ssl_client_cert`) to create an instance.
    """
    def __init__(self):
        self.credentials = None
        self.authtype = None
        self.authmount = None

    @classmethod
    def app_id(cls, app_id, user_id):
        i = cls()
        i.credentials = (app_id, user_id)
        i.authtype = "app-id"
        return i

    @classmethod
    def approle(cls, role_id, secret_id, mountpoint):
        i = cls()
        i.credentials = (role_id, secret_id)
        i.authmount = mountpoint
        i.authtype = "approle"
        return i

    @classmethod
    def ssl_client_cert(cls, certfile, keyfile):
        if not os.path.isfile(certfile) or not os.access(certfile, os.R_OK):
            raise Exception("File not found or not readable: %s" % certfile)

        if not os.path.isfile(keyfile) or not os.access(keyfile, os.R_OK):
            raise Exception("File not found or not readable: %s" % keyfile)

        i = cls()
        i.credentials = (certfile, keyfile)
        i.authtype = "ssl"
        return i

    @classmethod
    def token(cls, token, authtype="token"):
        """
        This method can be used to effect many authentication adapters, like
        token authenticaation and GitHub
        """
        i = cls()
        i.credentials = token
        i.authtype = authtype
        return i

    @classmethod
    def username_and_password(cls, username, password, authtype):
        """
        This method can be used for many authentication adapters, like okta, ldap, etc.
        """
        i = cls()
        i.credentials = (username, password)
        i.authtype = authtype
        return i

    @classmethod
    def role_and_jwt(cls, role, jwt, authtype):
        """
        This method can be used to effect many authentication adapters, like
        Kubernetes, Azure, GCP, and JWT/OIDC
        """
        i = cls()
        i.credentials = (role, jwt)
        i.authtype = authtype
        return i

    def authenticate(self, *args, **kwargs):
        if self.authtype == "token":
            cl = hvac.Client(token=self.credentials, *args, **kwargs)
        elif self.authtype == "app-id":
            cl = hvac.Client(*args, **kwargs)
            cl.auth_app_id(*self.credentials)
        elif self.authtype == "ssl":
            cl = hvac.Client(cert=self.credentials, *args, **kwargs)
            cl.auth.tls.login()
        else:
            cl = hvac.Client(*args, **kwargs)
            try:
                auth_adapter = getattr(cl.auth, self.authtype)
            except AttributeError:
                raise UnsupportedAuthMethodException

            auth_adapter.login(*self.credentials, mount_point=self.authmount)

        if not cl.is_authenticated():
            raise UnauthenticatedClientException
        return cl

def get_authenticated_client():
    i = None 
    vaulturl = config("VAULT_ADDR","http://localhost:8200/")
    if config("VAULT_TOKEN", None):
        i = VaultAuthenticator.token(config("VAULT_TOKEN"))
    elif config("VAULT_APPID", None) and config("VAULT_USERID", None):
        i = VaultAuthenticator.app_id(config("VAULT_APPID"), config("VAULT_USERID"))
    elif config("VAULT_ROLEID", None) and config("VAULT_SECRETID", None):
        i = VaultAuthenticator.approle(config("VAULT_ROLEID"), config("VAULT_SECRETID"))
    elif config("VAULT_SSLCERT", None) and config("VAULT_SSLKEY", None):
        i = VaultAuthenticator.ssl_client_cert(config("VAULT_SSLCERT"), config("VAULT_SSLKEY"))
    else:
        raise Exception("No suitable environment variable configured for authentication")
    return i.authenticate(url=vaulturl)
