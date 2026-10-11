"""simple_pac_file: Extract FindProxyForURL and DNS helpers from a PAC file."""

from .core import PacParseError, PacFile

__all__ = ["PacFile", "PacParseError"]
