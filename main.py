import json
from typing import Annotated
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from fastapi import Depends, FastAPI, HTTPException
from datetime import datetime, timedelta, UTC
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import jwt
from cryptography.hazmat.primitives.asymmetric import ec
import base64

from pydantic import BaseModel

from ldap import LDAPManager

app = FastAPI()
security = HTTPBasic()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_credentials=True,
    allow_headers=["*"]
)

LDAP_SERVERS = json.loads(open('orgs.json', 'r').read())
JWT_ALGORITHM = "ES256"
JWT_EXPIRE_MINUTES = 60
ISSUER = 'http://localhost:8080'
JWT_KEY_ID = "minio-key-id"


try:
    with open("ec_private_key.pem", "rb") as f:
        PRIVATE_KEY = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    with open("ec_public_key.pem", "rb") as f:
        PUBLIC_KEY = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
except FileNotFoundError:
    PRIVATE_KEY = ec.generate_private_key(ec.SECP256R1())
    PUBLIC_KEY = PRIVATE_KEY.public_key()

    with open("ec_private_key.pem", "wb") as f:
        f.write(PRIVATE_KEY.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open("ec_public_key.pem", "wb") as f:
        f.write(PUBLIC_KEY.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))


def create_jwt_token(username: str, org: str) -> dict:
    expire = datetime.now(UTC) + timedelta(minutes=JWT_EXPIRE_MINUTES)
    payload = {
        "sub": username,
        "org": org,
        "policy": "readwrite",
        "exp": int(expire.timestamp()),
        "iat": int(datetime.now(UTC).timestamp()),
        "iss": ISSUER,
        "aud": "minio",
    }
    return jwt.encode(payload, PRIVATE_KEY, algorithm=JWT_ALGORITHM, headers={"typ": "JWT", "alg": JWT_ALGORITHM, "kid": JWT_KEY_ID})


class LoginRequest(BaseModel):
    username: str
    password: str
    org: str | None = None


@app.post("/login")
def login(credentials: Annotated[HTTPBasicCredentials, Depends(security)], org: str = None) -> str:
    if not org:
        org = 'default'
    ldap = LDAP_SERVERS[org]
    client_ldap = LDAPManager(server_url=ldap['url'], base_dn=ldap['base_dn'])
    user_id_ldap = client_ldap.auth(credentials.username, credentials.password)

    if user_id_ldap is None:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_jwt_token(credentials.username, org)
    return token


@app.get("/jwks.json")
async def jwks():
    public_numbers = PUBLIC_KEY.public_numbers()

    x_bytes = public_numbers.x.to_bytes(32, 'big')
    y_bytes = public_numbers.y.to_bytes(32, 'big')

    def base64url_encode(data):
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')

    return {
        "keys": [{
            "kty": "EC",
            "kid": JWT_KEY_ID,
            "use": "sig",
            "crv": "P-256",
            "x": base64url_encode(x_bytes),
            "y": base64url_encode(y_bytes),
            "alg": JWT_ALGORITHM
        }]
    }


@app.get("/.well-known/openid-configuration")
def openid_config() -> dict[str, str | list]:
    return {
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/authorize",
        "token_endpoint": f"{ISSUER}/token",
        "userinfo_endpoint": f"{ISSUER}/userinfo",
        "jwks_uri": f"{ISSUER}/jwks.json",
        "scopes_supported": ["openid", "profile", "email"],
        "response_types_supported": ["code"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic"],
        "subject_types_supported": ["public"]
    }
