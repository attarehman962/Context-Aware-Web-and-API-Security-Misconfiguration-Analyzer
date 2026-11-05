"""Typed API errors rendered in the standard envelope.

Raise :class:`ApiError` from a route to return
``{"success": false, "error": {"code": ..., "message": ...}}`` with a specific
code (the codes are part of the API contract, docs/api-contract.md).
"""

from __future__ import annotations


class ApiError(Exception):
    def __init__(
        self, status_code: int, code: str, message: str, headers: dict[str, str] | None = None
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.headers = headers or {}  # e.g. Retry-After on 429
