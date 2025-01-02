from fastapi import APIRouter
from config.db import conn
from models.user import users
from schemas.index import User
import requests
import json
import os.path
import time
from jwcrypto import jwk, jwt
from jwcrypto.common import JWException
from fastapi import Header, HTTPException


WAITING_ROOM_API_URL = "http://localhost:8000/waiting-room"
WAITING_ROOM_EVENT_ID = "evnet-1"
ISSUER = os.environ.get("ISSUER")


def check_current_position(request_id: str):
    event_id = WAITING_ROOM_EVENT_ID
    params = {
        "event_id": event_id,
        "request_id": request_id
    }
    body = requests.get(WAITING_ROOM_API_URL + "/queue_num", params=params).json()
    return body["queue_number"]

def check_serving_number():
    body = requests.get(WAITING_ROOM_API_URL + "/serving_num", params={"event_id": WAITING_ROOM_EVENT_ID}).json()
    return body["serving_counter"]


def check_user_eligibility(request_id: str):
    if  check_current_position(request_id) <= check_serving_number():
        return True
    else:
        return False

def generate_token(event_id: str, request_id: str):
    data = {
        "event_id": event_id,
        "request_id": request_id
    }
    body = requests.post(WAITING_ROOM_API_URL + "/generate_token", json=data).json()
    return body




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
            print('error getting public key')
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
        print('signature is invalid or token has expired')
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




user = APIRouter()

@user.get("/assign_queue_number")
async def assign_queue_number():
    body = requests.post(WAITING_ROOM_API_URL + "/assign_queue_number", json={"event_id": WAITING_ROOM_EVENT_ID}).json()
    return {
        "request_id": body["api_request_id"]
    }
    
@user.get("/check_queue_number")
async def check_queue_number(request_id: str):
    if check_user_eligibility(request_id):
        return {
            "token": generate_token(WAITING_ROOM_EVENT_ID, request_id)
        }
    else: 
        return {
        "queue_number": f"Your current position is {check_current_position(request_id)}"
        }
    
@user.get("/")
async def get_all_users():
    return conn.execute(users.select()).mappings().all()

@user.get("/{id}")
async def get_single_user(id: int, authorization: str = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization token is missing")
    
    token = authorization.split(" ")[1] if " " in authorization else authorization
    if not verify_token(token):
        raise HTTPException(status_code=403, detail="Permission denied: Invalid token")
    
    return conn.execute(users.select().where(users.c.id == id)).mappings().all()

@user.post("/")
async def create_user(user: User):
    
    conn.execute(users.insert().values(
        name=user.name,
        email=user.email,
        password=user.password
    ))
    conn.commit()
    return conn.execute(users.select()).mappings().all()


@user.put("/{id}")
async def update_user(id: int, user: User):
    conn.execute(users.update(
        name=user.name,
        email=user.email,
        password=user.password
    ).where(users.c.id == id))
    conn.commit()
    return conn.execute(users.select()).mappings().all()

@user.delete("/{id}")
async def delete_user(id: int):
    conn.execute(users.delete().where(users.c.id == id))
    conn.commit()
    return conn.execute(users.select()).mappings().all()