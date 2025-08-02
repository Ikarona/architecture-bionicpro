import os
import time
import requests

from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, jwk
from jose.utils import base64url_decode

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

bearer = HTTPBearer()

KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://localhost:8080")
REALM         = os.getenv("KEYCLOAK_REALM", "reports-realm")
CLIENT_ID     = "reports-frontend"


def fetch_jwks_keys():
    """Try a few times to pull JWKS; on failure, raise a FastAPI HTTPException."""
    url = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/certs"
    for attempt in range(5):
        try:
            resp = requests.get(url, timeout=3)
            resp.raise_for_status()
            jwks = resp.json()
            return jwks["keys"]
        except Exception:
            time.sleep(2)
    raise HTTPException(503, "Keycloak JWKS endpoint unavailable")


def verify_token(
    credentials: HTTPAuthorizationCredentials = Depends(bearer)
):
    token = credentials.credentials
    keys = fetch_jwks_keys()
    try:
        header = jwt.get_unverified_header(token)
    except Exception:
        raise HTTPException(401, "Invalid token header")

    key_data = next((k for k in keys if k["kid"] == header.get("kid")), None)
    if not key_data:
        raise HTTPException(401, "Unknown key ID")

    public_key = jwk.construct(key_data)
    message, encoded_sig = token.rsplit(".", 1)
    if not public_key.verify(message.encode(), base64url_decode(encoded_sig.encode())):
        raise HTTPException(401, "Invalid signature")
    claims = jwt.get_unverified_claims(token)
    if claims.get("exp", 0) < time.time():
       raise HTTPException(401, "Token expired")
    aud = claims.get("aud")
    allowed = []
    if aud:
        allowed = aud if isinstance(aud, list) else [aud]
    else:
        azp = claims.get("azp")
        if azp:
            allowed = [azp]

    if CLIENT_ID not in allowed:
        raise HTTPException(401, "Invalid audience")

    roles = claims.get("realm_access", {}).get("roles", [])
    if "prothetic_user" not in roles:
        raise HTTPException(403, "Forbidden")

    return claims


@app.get("/reports")
def get_reports(user: dict = Depends(verify_token)):
    return {
        "user":   user.get("preferred_username"),
        "report": {
            "timestamp": int(time.time()),
            "data": [
                {"metric": "signal_strength",    "value": 0.87},
                {"metric": "response_time_ms",    "value": 95  }
            ]
        }
    }
