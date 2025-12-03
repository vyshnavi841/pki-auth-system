from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import base64
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# Import our TOTP helpers
from .utils import generate_totp_code, verify_totp_code

app = FastAPI()

SEED_FILE = "seed.txt"
PRIVATE_KEY_FILE = "student_private.pem"

# -------------------------------
# REQUEST MODELS
# -------------------------------

class DecryptSeedRequest(BaseModel):
    encrypted_seed: str

class Verify2FARequest(BaseModel):
    code: str


# -------------------------------
# ENDPOINT 1 — POST /decrypt-seed
# -------------------------------

@app.post("/decrypt-seed")
def decrypt_seed(data: DecryptSeedRequest):
    try:
        # load private key
        with open(PRIVATE_KEY_FILE, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )

        # decode base64 incoming seed
        encrypted_bytes = base64.b64decode(data.encrypted_seed)

        # decrypt using RSA-OAEP-SHA256
        decrypted = private_key.decrypt(
            encrypted_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # save decrypted hex seed
        with open(SEED_FILE, "wb") as f:
            f.write(decrypted)

        return {"status": "ok"}

    except Exception as e:
        raise HTTPException(status_code=500, detail="Decryption failed")


# -------------------------------
# ENDPOINT 2 — GET /generate-2fa
# -------------------------------

@app.get("/generate-2fa")
def generate_2fa():
    if not os.path.exists(SEED_FILE):
        raise HTTPException(status_code=500, detail="Seed not decrypted yet")

    with open(SEED_FILE, "rb") as f:
        hex_seed = f.read().strip().decode()

    code = generate_totp_code(hex_seed)
    return {"code": code, "valid_for": 30}


# -------------------------------
# ENDPOINT 3 — POST /verify-2fa
# -------------------------------

@app.post("/verify-2fa")
def verify_2fa(data: Verify2FARequest):
    if not os.path.exists(SEED_FILE):
        raise HTTPException(status_code=500, detail="Seed not decrypted yet")

    with open(SEED_FILE, "rb") as f:
        hex_seed = f.read().strip().decode()

    result = verify_totp_code(hex_seed, data.code)
    return {"valid": result}