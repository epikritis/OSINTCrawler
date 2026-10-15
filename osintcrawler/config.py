"""Settings loaded from environment variables / a local .env file.

Secret values are never logged or rendered; only the *names* of missing
variables are ever reported.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

ENV_KEYS = (
    "VT_API_KEY",
    "ABUSEIPDB_API_KEY",
    "OTX_API_KEY",
    "GREYNOISE_API_KEY",
    "ABUSECH_AUTH_KEY",
    "SHODAN_API_KEY",
    "SECURITYTRAILS_API_KEY",
    "URLSCAN_API_KEY",
    "IPINFO_TOKEN",
    "GOOGLE_SAFEBROWSING_API_KEY",
    "HIBP_API_KEY",
    "HUNTER_API_KEY",
    "EMAILREP_API_KEY",
    "NUMVERIFY_API_KEY",
    "NVD_API_KEY",
    "ETHERSCAN_API_KEY",
    "CHAINABUSE_API_KEY",
    "ANTHROPIC_API_KEY",
)


def _load_env_files() -> None:
    """Load .env from the CWD, then from the project root (no override of real env vars)."""
    load_dotenv(Path.cwd() / ".env", override=False)
    load_dotenv(Path(__file__).resolve().parent.parent / ".env", override=False)


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "") or default)
    except ValueError:
        return default


@dataclass
class Settings:
    keys: dict[str, str] = field(default_factory=dict)
    http_timeout: float = 15.0
    max_concurrency: int = 10
    default_phone_region: str | None = None
    anthropic_model: str = "claude-opus-5-5"
    user_agent: str = "OSINTCrawler/0.1 (+https://github.com/epikritis/OSINTCrawler)"

    @classmethod
    def from_env(cls, load_files: bool = True) -> "Settings":
        if load_files:
            _load_env_files()
        keys = {k: v.strip() for k in ENV_KEYS if (v := os.environ.get(k, "")) and v.strip()}
        region = (os.environ.get("DEFAULT_PHONE_REGION") or "").strip().upper() or None
        return cls(
            keys=keys,
            http_timeout=float(_int("HTTP_TIMEOUT", 15)),
            max_concurrency=max(1, _int("MAX_CONCURRENCY", 10)),
            default_phone_region=region,
            anthropic_model=(os.environ.get("ANTHROPIC_MODEL") or "claude-opus-5-5").strip(),
        )

    def key(self, name: str | None) -> str | None:
        return self.keys.get(name) if name else None

    def has(self, name: str | None) -> bool:
        return bool(self.key(name))
