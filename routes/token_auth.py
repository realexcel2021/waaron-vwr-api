import json
import os.path
import time

import requests
from jwcrypto import jwk, jwt
from jwcrypto.common import JWException
from vwr.common.diag import print_exception
from chalice import Chalice, Response

app = Chalice(app_name='token-authorizer')

WAITING_ROOM_EVENT_ID = os.environ.get("WAITING_ROOM_EVENT_ID")
WAITING_ROOM_API_URL = os.environ.get("WAITING_ROOM_API_URL")
ISSUER = os.environ.get("ISSUER")


def get_public_key():
    """
    This function is responsible for retrieving the
    public JWK from the closest location
    """
    # Bandit B108: /tmp directory is ephemeral as this is ran on Lambda
    local_key_file = "/tmp/jwks.json" # nosec
    key = {}
    if os.path.isfile(local_key_file):
        # retrieve from the local file
        with open(local_key_file, 'rt', encoding='utf-8') as cache_file:
            key = json.loads(cache_file.read())
    else:
        # retrieve from the core API
        api_endpoint = f'{WAITING_ROOM_API_URL}/public_key?event_id={WAITING_ROOM_EVENT_ID}'
        try:
            response = requests.get(api_endpoint, timeout=60)
            if response.status_code == 200:
                with open(local_key_file, 'wt', encoding='utf-8') as cache_file:
                    cache_file.write(response.text)
                key = json.loads(response.text)
        except (OSError, RuntimeError):
            print_exception()
    return key


def verify_token_sig(token):
    """
    This function is responsible for verifying a JWT token against public keys and returning
    verified claims within the token or False
    """
    # get the public JWK dictionary
    pubkey_dict = get_public_key()
    # recreate the token with public key verification
    try:
        key = jwk.JWK(**pubkey_dict)
        verified = jwt.JWT(key=key, jwt=token)
        return json.loads(verified.claims)
    except JWException:
        # signature is invalid or token has expired
        print_exception()
        return False


def verify_token(token, use='access'):
    """
    This function is responsible for verifying
    a JWT ID token contents
    """
    # get the verified claims
    verified_claims = verify_token_sig(token)
    if verified_claims:
        # verify the token expiration
        if time.time() > verified_claims.get('exp', 0):
            print('token is expired')
            return False
        # verify the app client id
        if verified_claims.get('aud', '') != WAITING_ROOM_EVENT_ID:
            print('token was not issued for this event')
            return False
        # verify the user pool uri
        if verified_claims.get('iss', '') != ISSUER:
            print('token from the wrong issuer')
            return False
        # verify the token use
        if verified_claims.get("token_use", "") != use:
            print(f'token was not issued for {use} use')
            return False
        return verified_claims
    return False

