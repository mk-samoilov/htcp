"""
HTCP Server Data Classes

Core data structures for server configuration and request handling.
"""

import json
import logging
from dataclasses import dataclass
from typing import Union, Optional
from htcp.backend.proto import Package


@dataclass
class Config:
    """
    Server configuration

    Attributes:
        host: Server bind address (e.g., "0.0.0.0", "127.0.0.1")
        port: Server port number
        name: Server name (used in logs)
        max_connections: Maximum simultaneous TCP connections
        handle_connections: Maximum concurrent request processing
        enable_logging: Enable logging
        logging_level: Logging level (e.g., logging.INFO)
        dh_encryption: Enable Diffie-Hellman encryption
        connect_passkey: Connection passkey (False to disable, or string)
    """
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
        """Validate configuration"""
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
    """
    Client connection information

    Attributes:
        ip: Client IP address
        port: Client port number
    """
    ip: str
    port: int

    def __str__(self) -> str:
        """String representation: ip:port"""
        return f"{self.ip}:{self.port}"


@dataclass
class Request:
    """
    Request object passed to handlers

    Attributes:
        package: The received package
        client: Client connection info
    """
    package: Package
    client: ClientInfo

    @property
    def data(self) -> bytes:
        """
        Get request data as bytes

        Returns:
            Raw bytes content from package
        """
        return self.package.content
