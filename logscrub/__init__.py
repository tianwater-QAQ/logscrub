"""logscrub — redact secrets and PII from text before sharing it.

>>> from logscrub import scrub
>>> scrub("token=ghp_" + "a"*36).text
'token=[REDACTED:github_token]'
"""
from .core import Result, scrub

__version__ = "0.2.0"
__all__ = ["scrub", "Result", "__version__"]
