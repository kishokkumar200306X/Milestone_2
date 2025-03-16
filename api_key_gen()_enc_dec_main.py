from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

from base64 import b64encode, b64decode
import os
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding

app = FastAPI()
aes_keys = {}
rsa_keys = {}


class KeyRequest(BaseModel):
    key_type: str
    key_size: int


class EncryptRequest(BaseModel):
    key_id: str
    plaintext: str
    algorithm: str


class DecryptRequest(BaseModel):
    key_id: str
    ciphertext: str
    algorithm: str



    

@app.post("/generate-key")
async def generate_key(request: KeyRequest):
    key_type = request.key_type
    key_size = request.key_size

    if key_type.upper() == "AES":
        key = os.urandom(key_size // 8)  # Generate AES key based on size (in bits)
        key_id = str(len(aes_keys) + 1)
        aes_keys[key_id] = {
            "key_type": "AES",
            "key_value": key  # Store the key as bytes
        }
        return {"key_id": key_id, "key_value": b64encode(key).decode('utf-8')}
    
    elif key_type.upper() == "RSA":
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        key_id = str(len(rsa_keys) + 1)
        rsa_keys[key_id] = {
            "key_type": "RSA",
            "private_key": private_pem,
            "public_key": public_pem
        }

        return {
            "key_id": key_id,
            "private_key": b64encode(private_pem).decode('utf-8'),
            "public_key": b64encode(public_pem).decode('utf-8')
        }
    
    raise HTTPException(status_code=400, detail="Unsupported key type or key size")

@app.post("/encrypt")
def encrypt(request: EncryptRequest):
    if request.algorithm.upper() == "AES":
        if request.key_id not in aes_keys:
            raise HTTPException(status_code=404, detail="AES Key not found")
        
        key = aes_keys[request.key_id]["key_value"]
        iv = os.urandom(16)  # Random IV for AES encryption
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Pad plaintext to a multiple of AES block size (16 bytes)
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(request.plaintext.encode()) + padder.finalize()

        # Encrypt and return ciphertext
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return {"ciphertext": b64encode(iv + ciphertext).decode('utf-8')}
    
    elif request.algorithm.upper() == "RSA":
        if request.key_id not in rsa_keys:
            raise HTTPException(status_code=404, detail="RSA Key not found")
        
        public_key_pem = rsa_keys[request.key_id]["public_key"]
        public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())

        ciphertext = public_key.encrypt(
            request.plaintext.encode(),
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return {"ciphertext": b64encode(ciphertext).decode('utf-8')}
    
    raise HTTPException(status_code=400, detail="Unsupported algorithm")

@app.post("/decrypt")
def decrypt(request: DecryptRequest):
    if request.algorithm.upper() == "AES":
        if request.key_id not in aes_keys:
            raise HTTPException(status_code=404, detail="AES Key not found")
        
        key = aes_keys[request.key_id]["key_value"]
        data = b64decode(request.ciphertext)
        iv, ciphertext = data[:16], data[16:]

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Unpad the decrypted plaintext
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        
        return {"plaintext": plaintext.decode().strip()}
    
    elif request.algorithm.upper() == "RSA":
        if request.key_id not in rsa_keys:
            raise HTTPException(status_code=404, detail="RSA Key not found")

        private_key_pem = rsa_keys[request.key_id]["private_key"]
        private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())

        ciphertext = b64decode(request.ciphertext)

        plaintext = private_key.decrypt(
            ciphertext,
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return {"plaintext": plaintext.decode()}
    
    raise HTTPException(status_code=400, detail="Unsupported algorithm")
