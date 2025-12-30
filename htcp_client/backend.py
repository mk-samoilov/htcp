"""
Client Backend Utilities

Low-level socket operations for HTCP client.
"""

import socket
import struct
from typing import Optional


class PackageIO:
    """Low-level package I/O operations for socket communication"""

    @staticmethod
    def send(sock: socket.socket, data: bytes) -> None:
        """
        Send complete message over socket

        Args:
            sock: Socket to send on
            data: Complete message with header (from Package.to_bytes())
        """
        sock.sendall(data)

    @staticmethod
    def receive(sock: socket.socket) -> bytes:
        """
        Receive complete message from socket

        Args:
            sock: Socket to receive from

        Returns:
            Complete message with header

        Raises:
            ConnectionError: If connection is closed
        """
        # Read 5-byte header
        header = PackageIO._recv_exact(sock, 5)

        # Parse length
        length = struct.unpack('>I', header[:4])[0]

        # Read payload (length includes header, so read length - 5 bytes)
        payload = PackageIO._recv_exact(sock, length - 5)

        return header + payload

    @staticmethod
    def _recv_exact(sock: socket.socket, n: int) -> bytes:
        """
        Receive exactly n bytes from socket

        Args:
            sock: Socket to receive from
            n: Number of bytes to receive

        Returns:
            Exactly n bytes

        Raises:
            ConnectionError: If connection is closed before receiving all bytes
        """
        data = b''
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                raise ConnectionError("Connection closed by peer")
            data += chunk
        return data

    @staticmethod
    def send_raw(sock: socket.socket, data: bytes) -> None:
        """
        Send raw data without length prefix (used for DH handshake)

        Args:
            sock: Socket to send on
            data: Raw data to send
        """
        # Send length prefix + data
        length = len(data)
        header = struct.pack('>I', length)
        sock.sendall(header + data)

    @staticmethod
    def receive_raw(sock: socket.socket) -> bytes:
        """
        Receive raw data with length prefix (used for DH handshake)

        Args:
            sock: Socket to receive from

        Returns:
            Raw data

        Raises:
            ConnectionError: If connection is closed
        """
        # Read 4-byte length prefix
        length_bytes = PackageIO._recv_exact(sock, 4)
        length = struct.unpack('>I', length_bytes)[0]

        # Read data
        return PackageIO._recv_exact(sock, length)
