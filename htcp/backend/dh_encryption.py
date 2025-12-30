import os
import json

from typing import Dict, Optional
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend


class DHEncryption:
    def __init__(self, key_size: int = 2048):
        self.key_size = key_size
        self.parameters: Optional[dh.DHParameters] = None
        self.private_key: Optional[dh.DHPrivateKey] = None
        self.public_key: Optional[dh.DHPublicKey] = None
        self.shared_key: Optional[bytes] = None
        self.aes_key: Optional[bytes] = None

    def generate_parameters(self) -> None:
        p = int(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
            "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
            "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
            "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
            "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
            "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
            "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
            "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
        )
        g = 2

        param_numbers = dh.DHParameterNumbers(p, g)
        self.parameters = param_numbers.parameters(default_backend())
        self._generate_keys()

    def load_parameters(self, p: int, g: int) -> None:
        param_numbers = dh.DHParameterNumbers(p, g)
        self.parameters = param_numbers.parameters(default_backend())
        self._generate_keys()

    def _generate_keys(self) -> None:
        if self.parameters is None:
            raise RuntimeError("Parameters not set")

        self.private_key = self.parameters.generate_private_key()
        self.public_key = self.private_key.public_key()

    def get_public_numbers(self) -> Dict[str, int]:
        if self.parameters is None or self.public_key is None:
            raise RuntimeError("Keys not generated")

        param_numbers = self.parameters.parameter_numbers()
        public_numbers = self.public_key.public_numbers()

        return {
            "p": param_numbers.p,
            "g": param_numbers.g,
            "public": public_numbers.y
        }

    def compute_shared_key(self, peer_public_key: int) -> None:
        if self.private_key is None or self.parameters is None:
            raise RuntimeError("Keys not generated")

        param_numbers = self.parameters.parameter_numbers()
        peer_public_numbers = dh.DHPublicNumbers(peer_public_key, param_numbers)
        peer_public_key_obj = peer_public_numbers.public_key(default_backend())

        self.shared_key = self.private_key.exchange(peer_public_key_obj)

        self.aes_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"htcp-aes-key",
            backend=default_backend()
        ).derive(self.shared_key)

    def encrypt(self, plaintext: bytes) -> bytes:
        if self.aes_key is None:
            raise RuntimeError("Shared key not computed")

        iv = os.urandom(16)

        cipher = Cipher(
            algorithms.AES(self.aes_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()

        padded = self._pad(plaintext)

        ciphertext = encryptor.update(padded) + encryptor.finalize()

        return iv + ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        if self.aes_key is None:
            raise RuntimeError("Shared key not computed")

        if len(ciphertext) < 16:
            raise ValueError("Ciphertext too short (missing IV)")

        iv = ciphertext[:16]
        encrypted_data = ciphertext[16:]

        cipher = Cipher(
            algorithms.AES(self.aes_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()

        padded = decryptor.update(encrypted_data) + decryptor.finalize()

        return self._unpad(padded)

    @staticmethod
    def _pad(data: bytes) -> bytes:
        block_size = 16
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding

    @staticmethod
    def _unpad(data: bytes) -> bytes:
        if len(data) == 0:
            raise ValueError("Cannot unpad empty data")

        padding_length = data[-1]

        if padding_length > 16 or padding_length > len(data):
            raise ValueError("Invalid padding")

        for i in range(padding_length):
            if data[-(i + 1)] != padding_length:
                raise ValueError("Invalid padding bytes")

        return data[:-padding_length]


def create_dh_init_message(dhl: DHEncryption) -> bytes:
    public_nums = dhl.get_public_numbers()
    message = {
        "type": "dh_init",
        "p": public_nums["p"],
        "g": public_nums["g"],
        "public": public_nums["public"]
    }
    return json.dumps(message).encode("utf-8")


def create_dh_reply_message(dhl: DHEncryption) -> bytes:
    public_nums = dhl.get_public_numbers()
    message = {
        "type": "dh_reply",
        "public": public_nums["public"]
    }
    return json.dumps(message).encode("utf-8")


def parse_dh_message(data: bytes) -> Dict:
    return json.loads(data.decode("utf-8"))
