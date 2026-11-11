"""LLM-backed URL token expansion for the NLP classifier.

The endpoint classifier's first step is to expand abbreviations in a URL path
(``usr`` -> ``user``, ``iam`` -> ``identity access management``). This module
performs that expansion with an LLM (OpenAI or Anthropic) when one is
configured, and falls back to the built-in abbreviation table otherwise -- so
the scanner never depends on an external API being reachable.

Provider APIs are called directly over httpx (no extra SDK dependency). Results
are cached per token so repeated tokens across a scan cost nothing.
"""

from __future__ import annotations

import json

import httpx

from app.config import settings
from app.utils.logging import get_logger

logger = get_logger(__name__)

_DEFAULT_MODELS = {
    "openai": "gpt-4o-mini",
    "anthropic": "claude-3-5-haiku-latest",
}

_PROMPT = (
    "You expand abbreviations found in the path segments of a web application "
    "URL, for security analysis. Given a JSON array of tokens, return a JSON "
    "object mapping each token to its most likely expanded form in full, "
    "lowercase words. Expand acronyms and shorthand (examples: 'usr'->'user', "
    "'iam'->'identity access management', 'txn'->'transaction', "
    "'auth'->'authentication', 'cfg'->'configuration', 'priv'->'privilege'). "
    "If a token is already a normal word, or you are unsure, map it to itself. "
    "Return ONLY the JSON object, no prose."
)


class LLMClient:
    """Expands URL abbreviations via an LLM, with a per-token cache."""

    def __init__(self, provider: str, api_key: str, model: str | None = None) -> None:
        self.provider = provider
        self.api_key = api_key
        self.model = model or _DEFAULT_MODELS.get(provider, "")
        self._cache: dict[str, str] = {}
        self.last_error: str | None = None

    async def expand_abbreviations(self, tokens: list[str]) -> dict[str, str]:
        """Return {token: expansion} for ``tokens`` (LLM for unknown short ones)."""
        # Only short alphabetic tokens are plausible abbreviations worth asking about.
        unknown = [
            t for t in dict.fromkeys(tokens) if t not in self._cache and t.isalpha() and len(t) <= 6
        ]
        if unknown:
            try:
                mapping = await self._query(unknown)
                for t in unknown:
                    self._cache[t] = str(mapping.get(t, t)).lower()
            except Exception as exc:  # noqa: BLE001 - fall back to identity/static
                self.last_error = str(exc)
                logger.info("LLM expansion failed (%s); using fallback", exc)
                for t in unknown:
                    self._cache[t] = t
        return {t: self._cache.get(t, t) for t in tokens}

    async def _query(self, tokens: list[str]) -> dict:
        payload = json.dumps(tokens)
        if self.provider == "openai":
            text = await self._call_openai(payload)
        elif self.provider == "anthropic":
            text = await self._call_anthropic(payload)
        else:
            raise ValueError(f"unknown LLM provider: {self.provider}")
        return _parse_json_object(text)

    async def _call_openai(self, user_content: str) -> str:
        async with httpx.AsyncClient(timeout=settings.REQUEST_TIMEOUT) as client:
            resp = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={
                    "model": self.model,
                    "temperature": 0,
                    "response_format": {"type": "json_object"},
                    "messages": [
                        {"role": "system", "content": _PROMPT},
                        {"role": "user", "content": user_content},
                    ],
                },
            )
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]

    async def _call_anthropic(self, user_content: str) -> str:
        async with httpx.AsyncClient(timeout=settings.REQUEST_TIMEOUT) as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": self.api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": self.model,
                    "max_tokens": 512,
                    "system": _PROMPT,
                    "messages": [{"role": "user", "content": user_content}],
                },
            )
            resp.raise_for_status()
            blocks = resp.json().get("content", [])
            return "".join(b.get("text", "") for b in blocks if b.get("type") == "text")


def _parse_json_object(text: str) -> dict:
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        text = text[text.find("{") :]
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end != -1:
        text = text[start : end + 1]
    obj = json.loads(text)
    return {str(k).lower(): str(v).lower() for k, v in obj.items()}


_client: LLMClient | None = None
_initialized = False


def get_llm_client() -> LLMClient | None:
    """Return a configured LLM client, or None if LLM expansion is disabled."""
    global _client, _initialized
    if _initialized:
        return _client
    _initialized = True
    if not settings.LLM_ENABLED:
        _client = None
        return None
    provider = settings.LLM_PROVIDER
    key = settings.OPENAI_API_KEY if provider == "openai" else settings.ANTHROPIC_API_KEY
    if not key:
        logger.info("LLM enabled but no API key for provider '%s'; using fallback", provider)
        _client = None
        return None
    _client = LLMClient(provider, key, settings.LLM_MODEL or None)
    logger.info("LLM token expansion enabled (provider=%s)", provider)
    return _client
