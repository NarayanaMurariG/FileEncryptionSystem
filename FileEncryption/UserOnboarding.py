from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
from shutil import copyfile


def encodeBytesToString(bytes):
    return b64encode(bytes).decode('utf-8')


def decodeStringToBytes(str):
    return b64decode(str)


def generatePublicPrivateKeys():
    privateKey = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    publicKey = privateKey.public_key()

    pemPvt = privateKey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    pemPbc = publicKey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # print(pemPvt)
    # print(pemPbc)
    # from utils import encodeBytesToString
    return encodeBytesToString(pemPvt), encodeBytesToString(pemPbc)
