"""Gets the machine architecture."""

from platform import machine

PLATFORMS = {"x86_64": "amd64", "aarch64": "arm64"}

architecture: str = PLATFORMS.get(machine(), "amd64")

__all__ = ("architecture",)
