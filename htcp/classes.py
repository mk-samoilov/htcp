import logging

from dataclasses import dataclass
from typing import Union
from .backend.proto import Package


@dataclass
class Config:
    host: str
    port: int
    name: str = "htcp_server"
    max_connections: int = 100
    handle_connections: int = 90
    enable_logging: bool = True
    logging_level: int = logging.INFO
    dh_encryption: bool = False
    connect_passkey: Union[bool, str] = False

    def __post_init__(self):
        if self.handle_connections > self.max_connections:
            raise ValueError(
                f"handle_connections ({self.handle_connections}) cannot exceed "
                f"max_connections ({self.max_connections})"
            )

        if self.max_connections < 1:
            raise ValueError("max_connections must be at least 1")

        if self.handle_connections < 1:
            raise ValueError("handle_connections must be at least 1")


@dataclass
class ClientInfo:
    ip: str
    port: int

    def __str__(self) -> str:
        return f"{self.ip}:{self.port}"


@dataclass
class Request:
    package: Package
    client: ClientInfo

    @property
    def data(self) -> bytes:
        return self.package.content
