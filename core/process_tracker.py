"""Best-effort process context; endpoint attribution is intentionally unavailable by default."""
from __future__ import annotations

import getpass
import os


class ProcessTracker:
    @staticmethod
    def context() -> tuple[str, str]:
        """Return user and a conservative process attribution statement.

        Watchdog callbacks do not reliably expose the originating process on all platforms.
        """
        return getpass.getuser(), f"unavailable (monitor pid {os.getpid()})"
