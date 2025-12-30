import asyncio
import logging
import struct

from typing import Optional

from htcp.classes import Config, ClientInfo, Request
from htcp.request_handler import RequestHandler
from htcp.backend.proto import Package, create_error_package
from htcp.backend.dh_encryption import DHEncryption, create_dh_init_message, parse_dh_message


class Server:
    def __init__(self, config: Config):
        self.config = config

        self.rh = RequestHandler()

        self.logger = self._setup_logging()

        self.active_connections = 0

        self.connection_semaphore = asyncio.Semaphore(config.max_connections)
        self.processing_semaphore = asyncio.Semaphore(config.handle_connections)

        self.server: Optional[asyncio.Server] = None

    def _setup_logging(self) -> logging.Logger:
        logger = logging.getLogger(f"htcp.{self.config.name}")
        logger.setLevel(
            self.config.logging_level if self.config.enable_logging else logging.CRITICAL
        )

        if self.config.enable_logging and not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    async def up(self) -> None:
        self.server = await asyncio.start_server(
            self._handle_client,
            self.config.host,
            self.config.port
        )

        self.logger.info(
            f"Endpoint started on {self.config.host}:{self.config.port}"
        )

        async with self.server:
            await self.server.serve_forever()

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter
    ) -> None:
        async with self.connection_semaphore:
            self.active_connections += 1
            addr = writer.get_extra_info("peername")
            self.logger.debug(f"Connection from {addr}")

            encryption: Optional[DHEncryption] = None

            try:
                if self.config.dh_encryption:
                    encryption = await self._perform_handshake(reader, writer)
                    if encryption is None:
                        self.logger.warning(f"DH handshake failed for {addr}")
                        return

                if self.config.connect_passkey:
                    if not await self._validate_passkey(reader, writer, addr, encryption):
                        return

                while True:
                    package = await self._read_package(reader, encryption)
                    if package is None:
                        break

                    async with self.processing_semaphore:
                        await self._process_request(package, writer, addr, encryption)

            except asyncio.CancelledError:
                self.logger.debug(f"Connection cancelled: {addr}")

            except ConnectionError as e:
                self.logger.debug(f"Connection error from {addr}: {e}")

            except Exception as e:
                self.logger.error(f"Error handling client {addr}: {e}", exc_info=True)

            finally:
                try:
                    writer.close()
                    await writer.wait_closed()
                except ExceptionGroup:
                    pass
                self.active_connections -= 1
                self.logger.debug(f"Connection closed: {addr}")

    async def _perform_handshake(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter
    ) -> Optional[DHEncryption]:
        try:
            encryption = DHEncryption()
            encryption.generate_parameters()

            dh_init = create_dh_init_message(encryption)
            await self._send_raw(writer, dh_init)

            dh_reply_data = await self._receive_raw(reader)
            dh_reply = parse_dh_message(dh_reply_data)

            if dh_reply.get("type") != "dh_reply":
                self.logger.warning(f"Expected dh_reply, got {dh_reply.get("type")}")
                return None

            encryption.compute_shared_key(dh_reply["public"])

            self.logger.debug("DH handshake completed successfully")
            return encryption

        except Exception as e:
            self.logger.error(f"DH handshake error: {e}", exc_info=True)
            return None

    async def _validate_passkey(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        addr: tuple,
        encryption: Optional[DHEncryption]
    ) -> bool:
        try:
            package = await self._read_package(reader, encryption)

            if package is None:
                self.logger.warning(f"No auth package from {addr}")
                return False

            if package.transaction != "_auth":
                self.logger.warning(f"Expected _auth transaction from {addr}, got {package.transaction}")
                return False

            client_passkey = package.content.get("passkey")
            if client_passkey != self.config.connect_passkey:
                self.logger.warning(f"Invalid passkey from {addr}")
                return False

            self.logger.debug(f"Passkey validated for {addr}")
            return True

        except Exception as e:
            self.logger.error(f"Passkey validation error: {e}", exc_info=True)
            return False

    async def _read_package(
        self,
        reader: asyncio.StreamReader,
        encryption: Optional[DHEncryption]
    ) -> Optional[Package]:
        try:
            header = await reader.readexactly(5)

            length = struct.unpack(">I", header[:4])[0]
            flags = header[4]

            payload = await reader.readexactly(length - 5)

            if encryption and Package.is_encrypted(header + payload):
                payload = encryption.decrypt(payload)

                new_length = 5 + len(payload)
                header = struct.pack(">I", new_length) + bytes([flags])

            data = header + payload
            return Package.from_bytes(data)

        except asyncio.IncompleteReadError:
            return None

        except Exception as e:
            self.logger.error(f"Error reading package: {e}", exc_info=True)
            return None

    async def _send_package(
        self,
        writer: asyncio.StreamWriter,
        package: Package,
        encryption: Optional[DHEncryption]
    ) -> None:
        try:
            data = package.to_bytes(
                encrypted=encryption is not None,
                is_response=True
            )

            if encryption:
                flags = data[4]
                payload = data[5:]

                encrypted_payload = encryption.encrypt(payload)

                new_length = 5 + len(encrypted_payload)
                new_header = struct.pack(">I", new_length) + bytes([flags])

                data = new_header + encrypted_payload

            writer.write(data)
            await writer.drain()

        except Exception as e:
            self.logger.error(f"Error sending package: {e}", exc_info=True)
            raise

    async def _process_request(
        self,
        package: Package,
        writer: asyncio.StreamWriter,
        addr: tuple,
        encryption: Optional[DHEncryption]
    ) -> None:
        request = Request(
            package=package,
            client=ClientInfo(ip=addr[0], port=addr[1])
        )

        try:
            response_data = await self.rh.handle(request)

            response_pkg = Package(
                transaction=package.transaction,
                content=response_data,
                uuid=package.uuid,
                from_addr=f"{self.config.host}:{self.config.port}"
            )

            await self._send_package(writer, response_pkg, encryption)

            self.logger.debug(f"Processed {package.transaction} from {addr}")

        except Exception as e:
            self.logger.error(f"Handler error for {package.transaction}: {e}", exc_info=True)

            error_pkg = create_error_package(
                transaction=package.transaction,
                error_message=str(e),
                request_uuid=package.uuid
            )
            error_pkg.from_addr = f"{self.config.host}:{self.config.port}"

            try:
                await self._send_package(writer, error_pkg, encryption)
            except ExceptionGroup:
                pass

    @staticmethod
    async def _send_raw(writer: asyncio.StreamWriter, data: bytes) -> None:
        length = struct.pack(">I", len(data))
        writer.write(length + data)
        await writer.drain()

    @staticmethod
    async def _receive_raw(reader: asyncio.StreamReader) -> bytes:
        length_bytes = await reader.readexactly(4)
        length = struct.unpack(">I", length_bytes)[0]
        return await reader.readexactly(length)
