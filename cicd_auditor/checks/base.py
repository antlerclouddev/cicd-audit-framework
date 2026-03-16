"""
checks/base.py
--------------
Abstract base class for every audit check.

WHY A BASE CLASS?
    All checks share the same interface: they receive the parsed YAML
    document + the raw file text, and they return a list of Findings.
    Enforcing this contract via ABC makes it impossible to forget to
    implement `run()` and keeps the orchestrator (auditor.py) simple —
    it never needs to know which specific check it is calling.

EXTENSION GUIDE
    To add a new check:
        1. Create a new file in cicd_auditor/checks/
        2. Subclass BaseCheck
        3. Fill in ID, TITLE, DESCRIPTION
        4. Implement run() → list[Finding]
        5. Import + register in cicd_auditor/checks/__init__.py
"""

from abc import ABC, abstractmethod
from typing import Any

from ..models import Finding


class BaseCheck(ABC):
    """
    Every check must declare three class-level attributes and implement run().

    Class attributes
    ----------------
    ID          : Unique code like "SEC-001".  Used in reports and CI annotations.
    TITLE       : Short human label, e.g. "Hardcoded Secret Detected"
    DESCRIPTION : One or two sentences explaining what this check looks for.
    """

    ID:          str = ""
    TITLE:       str = ""
    DESCRIPTION: str = ""

    @abstractmethod
    def run(
        self,
        file_path: str,
        raw_text:  str,
        parsed:    dict[str, Any],
    ) -> list[Finding]:
        """
        Execute the check against a single pipeline file.

        Parameters
        ----------
        file_path : Relative path to the pipeline file (for Finding.file_path)
        raw_text  : The raw file content as a string (for line-number scanning)
        parsed    : The YAML-parsed dict representation of the file

        Returns
        -------
        A (possibly empty) list of Finding instances.
        Return [] when no issues are found — never raise an exception.
        """
        ...

    # ------------------------------------------------------------------ #
    # Helpers shared by multiple checks                                    #
    # ------------------------------------------------------------------ #

    @staticmethod
    def line_of(raw_text: str, snippet: str) -> int | None:
        """Return the 1-based line number where `snippet` first appears."""
        for i, line in enumerate(raw_text.splitlines(), start=1):
            if snippet in line:
                return i
        return None
