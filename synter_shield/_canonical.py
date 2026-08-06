import math
from typing import Any, Set

import rfc8785

MAX_SAFE_JSON_INTEGER = 9_007_199_254_740_991


def validate_json(value: Any, seen: Set[int] = None) -> None:
    if seen is None:
        seen = set()
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_JSON_INTEGER:
            raise ValueError("JSON integers must be safe IEEE-754 integers")
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("JSON numbers must be finite")
        if value.is_integer() and abs(value) > MAX_SAFE_JSON_INTEGER:
            raise ValueError("JSON integers must be safe IEEE-754 integers")
        return
    if not isinstance(value, (dict, list)):
        raise TypeError("Unsupported JSON value")
    marker = id(value)
    if marker in seen:
        raise ValueError("Cyclic JSON value")
    seen.add(marker)
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("JSON object keys must be strings")
            validate_json(item, seen)
    else:
        for item in value:
            validate_json(item, seen)
    seen.remove(marker)


def canonical_json(value: Any) -> bytes:
    validate_json(value)
    return rfc8785.dumps(value)


def secret_bytes(secret_key: str) -> bytes:
    if not isinstance(secret_key, str) or len(secret_key.encode("utf-8")) < 32:
        raise ValueError("Secret key must contain at least 32 UTF-8 bytes.")
    return secret_key.encode("utf-8")
