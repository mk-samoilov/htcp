import json

from typing import Any, Dict, List, Union


def dict_to_bytes(data: Dict[str, Any]) -> bytes:
    return json.dumps(data).encode("utf-8")


def bytes_to_dict(data: bytes) -> Dict[str, Any]:
    return json.loads(data.decode("utf-8"))


def list_to_bytes(data: List[Any]) -> bytes:
    return json.dumps(data).encode("utf-8")


def bytes_to_list(data: bytes) -> List[Any]:
    return json.loads(data.decode("utf-8"))


def str_to_bytes(data: str) -> bytes:
    return data.encode("utf-8")


def bytes_to_str(data: bytes) -> str:
    return data.decode("utf-8")


def json_encode(data: Union[Dict, List, str, int, float, bool, None]) -> bytes:
    return json.dumps(data).encode("utf-8")


def json_decode(data: bytes) -> Union[Dict, List, str, int, float, bool, None]:
    return json.loads(data.decode("utf-8"))
