"""Local development entry point.

Run with ``python run.py`` to start the API on :8000. In Docker/production the
app is served by ``uvicorn app.main:app`` directly.
"""

from __future__ import annotations

import uvicorn

from app.config import settings


def main() -> None:
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",  # noqa: S104 - dev server, reachable from containers
        port=8000,
        reload=settings.DEBUG,
    )


if __name__ == "__main__":
    main()
