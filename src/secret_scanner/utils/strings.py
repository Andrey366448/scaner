from __future__ import annotations


def mask_secret(value: str) -> str:
    if len(value) <= 8:
        return "***"
    return f"{value[:4]}***{value[-4:]}"


def is_binary_bytes(data: bytes) -> bool:
    if not data:
        return False
    if b"\x00" in data:
        return True
    text_chars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)))
    non_text = data.translate(None, text_chars)
    return len(non_text) / len(data) > 0.30
