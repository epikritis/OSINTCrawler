"""Vercel serverless entry point: exposes the FastAPI ``app``."""

from osintcrawler.web.app import app  # noqa: F401
