"""Camouflage Cloak source package bootstrap.

This package intentionally keeps imports lazy so the application can fail with
clear, actionable errors instead of crashing during module import.
"""

from __future__ import annotations

import importlib
import logging

__version__ = "0.1.0"
__author__ = "Camouflage Cloak"

__all__ = [
    "__version__",
    "__author__",
    "get_package_info",
    "safe_import",
]


def get_package_info() -> dict:
    """Return a small metadata payload for the source package."""
    return {
        "name": "Camouflage-Cloak",
        "package": "src",
        "version": __version__,
        "author": __author__,
    }


def safe_import(module_name: str, attr: str | None = None, default=None):
    """Safely import a module or symbol with graceful fallback.

    This prevents one missing component from crashing the entire package when
    optional or environment-specific modules are unavailable.
    """
    logger = logging.getLogger(__name__)
    try:
        module = importlib.import_module(module_name)
    except Exception as exc:  # pragma: no cover - defensive fallback
        logger.warning("Unable to import %s: %s", module_name, exc)
        return default

    if attr is None:
        return module

    try:
        return getattr(module, attr)
    except AttributeError as exc:  # pragma: no cover - defensive fallback
        logger.warning("Module %s has no attribute %s: %s", module_name, attr, exc)
        return default
