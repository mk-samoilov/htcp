"""
HTCP Client Implementation

Synchronous TCP client for High TCP protocol.
"""

import socket
import struct
from typing import Optional
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from htcp.backend.proto import Package
from htcp.backend.dh_encryption import DHEncryption, create_dh_reply_message, parse_dh_message
from htcp_client.backend import PackageIO


class Client:
    """
    Synchronous TCP client for HTCP protocol

    Provides simple API: connect(), ask(), send(), receive(), close()
    """

    def __init__(self, host: str, port: int, dh_encryption: bool = False, passkey: str = "-"):
        """
        Initialize HTCP client

        Args:
            host: Server hostname or IP
            port: Server port
            dh_encryption: Enable Diffie-Hellman encryption
            passkey: Connection passkey (use "-" to disable)
        """
        self.host = host
        self.port = port
        self.dh_encryption = dh_encryption
        self.passkey = passkey if passkey != "-" else None
        self.socket: Optional[socket.socket] = None
        self.encryption: Optional[DHEncryption] = None
        self._connected = False

    def connect(self) -> None:
        """
        Establish connection to server

        Performs DH handshake if encryption is enabled.
        Sends passkey if required.

        Raises:
            ConnectionError: If connection fails
        """
        # Create socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            # Connect to server
            self.socket.connect((self.host, self.port))
            self._connected = True

            # Perform DH handshake if encryption enabled
            if self.dh_encryption:
                self._perform_handshake()

            # Send passkey if required
            if self.passkey:
                self._send_passkey()

        except Exception as e:
            if self.socket:
                self.socket.close()
            self._connected = False
            raise ConnectionError(f"Failed to connect: {e}")

    def _perform_handshake(self) -> None:
        """
        Perform DH key exchange with server

        Protocol:
        1. Receive: server's p, g, public key
        2. Send: client's public key
        3. Compute shared secret

        Raises:
            RuntimeError: If handshake fails
        """
        try:
            # Receive DH init from server
            dh_init_data = PackageIO.receive_raw(self.socket)
            dh_init = parse_dh_message(dh_init_data)

            if dh_init.get('type') != 'dh_init':
                raise RuntimeError(f"Expected dh_init, got {dh_init.get('type')}")

            # Initialize client DH with server's parameters
            self.encryption = DHEncryption()
            self.encryption.load_parameters(dh_init['p'], dh_init['g'])

            # Compute shared key using server's public key
            self.encryption.compute_shared_key(dh_init['public'])

            # Send client's public key to server
            dh_reply = create_dh_reply_message(self.encryption)
            PackageIO.send_raw(self.socket, dh_reply)

        except Exception as e:
            raise RuntimeError(f"DH handshake failed: {e}")

    def _send_passkey(self) -> None:
        """
        Send passkey to server for authentication

        Uses special "_auth" transaction.

        Raises:
            RuntimeError: If passkey validation fails
        """
        auth_pkg = Package(
            transaction="_auth",
            content={"passkey": self.passkey}
        )

        # Send auth package
        self.send(auth_pkg)

        # Note: Server will close connection if passkey is invalid
        # Client will detect this on next receive

    def ask(self, package: Package) -> Package:
        """
        Send request and wait for response

        Args:
            package: Request package

        Returns:
            Response package

        Raises:
            ValueError: If response UUID doesn't match request
            ConnectionError: If connection is closed
        """
        if not self._connected:
            self.connect()

        # Send request
        self.send(package)

        # Receive response
        response = self.receive()

        # Validate UUID correlation
        if response.uuid != package.uuid:
            raise ValueError(
                f"Response UUID mismatch: expected {package.uuid}, got {response.uuid}"
            )

        return response

    def send(self, package: Package) -> None:
        """
        Send package without waiting for response

        Args:
            package: Package to send

        Raises:
            ConnectionError: If not connected
        """
        if not self._connected:
            self.connect()

        # Serialize package
        data = package.to_bytes(encrypted=self.dh_encryption, is_response=False)

        # Encrypt if needed
        if self.dh_encryption and self.encryption:
            # Extract header (5 bytes) and payload
            flags = data[4]
            payload = data[5:]

            # Encrypt payload
            encrypted_payload = self.encryption.encrypt(payload)

            # Rebuild header with new length
            new_length = 5 + len(encrypted_payload)
            new_header = struct.pack('>I', new_length) + bytes([flags])

            # Reconstruct message
            data = new_header + encrypted_payload

        # Send
        PackageIO.send(self.socket, data)

    def receive(self) -> Package:
        """
        Receive package from server

        Returns:
            Received package

        Raises:
            ConnectionError: If not connected
        """
        if not self._connected:
            raise ConnectionError("Not connected to server")

        # Receive raw data
        data = PackageIO.receive(self.socket)

        # Decrypt if needed
        if self.dh_encryption and self.encryption:
            # Check if message is encrypted
            if Package.is_encrypted(data):
                # Extract flags and encrypted payload
                flags = data[4]
                encrypted_payload = data[5:]

                # Decrypt payload
                payload = self.encryption.decrypt(encrypted_payload)

                # Rebuild header with original payload length
                new_length = 5 + len(payload)
                new_header = struct.pack('>I', new_length) + bytes([flags])

                # Reconstruct message
                data = new_header + payload

        # Parse package
        return Package.from_bytes(data)

    def close(self) -> None:
        """Close connection to server"""
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            finally:
                self._connected = False
                self.socket = None
                self.encryption = None

    def __enter__(self):
        """Context manager entry"""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()
        return False
