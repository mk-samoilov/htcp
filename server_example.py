from htcp import Server, Config, Request
from htcp.utils import dict_to_bytes, bytes_to_dict

import logging
import asyncio


myconf = Config(
    host="localhost",
    port=9576,
    name="test_server",
    max_connections=100,
    handle_connections=90,
    enable_logging=True,
    logging_level=logging.INFO,
    dh_encryption=True,
    connect_passkey=False
)

serv = Server(config=myconf)


@serv.rh.reg_handler(trans_code="get_my_ip")
def get_my_ip(request: Request) -> bytes:
    req_data = bytes_to_dict(request.data)
    print(f"Request data: {req_data}")

    print(f"Client IP: {request.client.ip}")
    print(f"Client Port: {request.client.port}")
    print(f"Package from: {request.package.from_addr}")
    print(f"Transaction: {request.package.transaction}")
    print(f"UUID: {request.package.uuid}")

    response = {"your_ip": request.client.ip}
    return dict_to_bytes(response)


@serv.rh.reg_handler(trans_code="echo")
def echo(request: Request) -> bytes:
    req_data = bytes_to_dict(request.data)

    response = {
        "echo": req_data,
        "from": f"{request.client.ip}:{request.client.port}"
    }

    return dict_to_bytes(response)


@serv.rh.reg_handler(trans_code="ping")
def ping(request: Request) -> bytes:
    return dict_to_bytes({"status": "pong"})


@serv.rh.reg_handler(trans_code="get_server_info")
def get_server_info(request: Request) -> bytes:
    response = {
        "server_name": serv.config.name,
        "active_connections": serv.active_connections,
        "encryption_enabled": serv.config.dh_encryption,
        "max_connections": serv.config.max_connections,
        "handle_connections": serv.config.handle_connections
    }

    return dict_to_bytes(response)


async def main():
    try:
        await serv.up()
    except KeyboardInterrupt:
        print("\nShutting down server...")


if __name__ == "__main__":
    asyncio.run(main())
