"""
HTCP Client Example

Example client demonstrating various client operations.
Using utils for convenient JSON/bytes conversions.
"""

from htcp_client import Client, Package
from htcp_client.utils import dict_to_bytes, bytes_to_dict
import time


def main():
    client = Client(
        host="localhost",
        port=9576,
        dh_encryption=True,
        passkey="-"
    )
    print("Connected to server")

    try:
        print("Connected!")

        print("\n1. Testing 'get_my_ip' transaction:")
        pkg = Package(
            transaction="get_my_ip",
            content=dict_to_bytes({})
        )
        response = client.ask(package=pkg)
        response_data = bytes_to_dict(response.content)
        print(f"   Server says my IP is: {response_data.get('your_ip')}")
        print(f"   Response UUID: {response.uuid}")

        print("\n2. Testing 'echo' transaction:")
        echo_data = {"message": "Hello, HTCP!", "timestamp": time.time()}
        echo_pkg = Package(
            transaction="echo",
            content=dict_to_bytes(echo_data)
        )
        echo_response = client.ask(package=echo_pkg)
        echo_resp_data = bytes_to_dict(echo_response.content)
        print(f"   Echo response: {echo_resp_data.get('echo')}")
        print(f"   From: {echo_resp_data.get('from')}")

        print("\n3. Testing 'ping' transaction:")
        ping_pkg = Package(
            transaction="ping",
            content=dict_to_bytes({})
        )
        ping_response = client.ask(package=ping_pkg)
        ping_resp_data = bytes_to_dict(ping_response.content)
        print(f"   Ping response: {ping_resp_data.get('status')}")

        print("\n4. Testing 'get_server_info' transaction:")
        info_pkg = Package(
            transaction="get_server_info",
            content=dict_to_bytes({})
        )
        info_response = client.ask(package=info_pkg)
        info_data = bytes_to_dict(info_response.content)
        print(f"   Server name: {info_data.get('server_name')}")
        print(f"   Active connections: {info_data.get('active_connections')}")
        print(f"   Encryption enabled: {info_data.get('encryption_enabled')}")
        print(f"   Max connections: {info_data.get('max_connections')}")

        print("\n5. Testing send() method (fire and forget):")
        send_data = {"note": "This is sent without waiting for response"}
        send_pkg = Package(
            transaction="echo",
            content=dict_to_bytes(send_data)
        )
        client.send(package=send_pkg)
        print("   Sent package without waiting for response")

        print("All tests completed successfully!")

    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()

    finally:
        client.close()
        print("\nConnection closed")


if __name__ == "__main__":
    main()
