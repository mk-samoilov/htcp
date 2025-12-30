import json
import struct
import uuid as uuid_module
import base64

from dataclasses import dataclass
from typing import Optional


FLAG_ENCRYPTED = 0x01  # Bit 0: Encrypted
FLAG_PASSKEY = 0x02    # Bit 1: Passkey required
FLAG_RESPONSE = 0x04   # Bit 2: Response (vs request)


@dataclass
class Package:
    transaction: str
    content: bytes
    uuid: Optional[str] = None
    from_addr: Optional[str] = None
    protocol_version: Optional[str] = None
    protocol_id: Optional[int] = None
    passkey: Optional[str] = None

    def __post_init__(self):
        if self.uuid is None:
            self.uuid = str(uuid_module.uuid4())

        if self.protocol_version is None:
            from ..version import protocol_version
            self.protocol_version = protocol_version

        if self.protocol_id is None:
            from ..version import protocol_backward_compatibility_id
            self.protocol_id = protocol_backward_compatibility_id

    def to_json(self) -> str:
        data = {
            "protocol_version": self.protocol_version,
            "protocol_id": self.protocol_id,
            "uuid": self.uuid,
            "transaction": self.transaction,
            "from": self.from_addr,
            "content": base64.b64encode(self.content).decode("ascii"),
        }

        if self.passkey is not None:
            data["passkey"] = self.passkey

        return json.dumps(data)

    def to_bytes(self, encrypted: bool = False, is_response: bool = False) -> bytes:
        payload = self.to_json().encode("utf-8")

        flags = 0
        if encrypted:
            flags |= FLAG_ENCRYPTED
        if self.passkey is not None:
            flags |= FLAG_PASSKEY
        if is_response:
            flags |= FLAG_RESPONSE

        total_length = 5 + len(payload)
        header = struct.pack(">I", total_length) + bytes([flags])

        return header + payload

    @classmethod
    def from_bytes(cls, data: bytes) -> "Package":
        if len(data) < 5:
            raise ValueError("Data too short for HTCP message")

        length = struct.unpack(">I", data[:4])[0]

        if len(data) != length:
            raise ValueError(f"Length mismatch: header says {length}, got {len(data)}")

        payload = data[5:].decode("utf-8")
        json_data = json.loads(payload)

        content_bytes = base64.b64decode(json_data["content"])

        return cls(
            transaction=json_data["transaction"],
            content=content_bytes,
            uuid=json_data.get("uuid"),
            from_addr=json_data.get("from"),
            protocol_version=json_data.get("protocol_version"),
            protocol_id=json_data.get("protocol_id"),
            passkey=json_data.get("passkey")
        )

    @staticmethod
    def get_flags(data: bytes) -> int:
        if len(data) < 5:
            raise ValueError("Data too short for header")
        return data[4]

    @staticmethod
    def is_encrypted(data: bytes) -> bool:
        return bool(Package.get_flags(data) & FLAG_ENCRYPTED)

    @staticmethod
    def is_response(data: bytes) -> bool:
        return bool(Package.get_flags(data) & FLAG_RESPONSE)

    @staticmethod
    def has_passkey(data: bytes) -> bool:
        return bool(Package.get_flags(data) & FLAG_PASSKEY)


def create_error_package(transaction: str, error_message: str, request_uuid: Optional[str] = None) -> Package:
    error_dict = {"error": error_message}
    content_bytes = json.dumps(error_dict).encode("utf-8")

    return Package(
        transaction=transaction,
        content=content_bytes,
        uuid=request_uuid if request_uuid else str(uuid_module.uuid4())
    )
