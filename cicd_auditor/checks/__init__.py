"""
checks/__init__.py
------------------
Central registry of all available audit checks.

WHY A REGISTRY?
    The orchestrator (auditor.py) imports ALL_CHECKS and runs each one.
    Adding a new check is a two-step process:
        1. Create your check class (subclass BaseCheck) in a new file
        2. Import it here and add an instance to ALL_CHECKS

    No other file needs to change.
"""

from .action_versions import ActionVersionsCheck
from .branch_protection import BranchProtectionCheck
from .permissions import PermissionsCheck
from .secrets import SecretsCheck
from .test_gates import TestGatesCheck
from .timeouts import TimeoutsCheck

# Order matters for report presentation — security checks first, then efficiency
ALL_CHECKS = [
    SecretsCheck(),
    ActionVersionsCheck(),
    PermissionsCheck(),
    BranchProtectionCheck(),
    TestGatesCheck(),
    TimeoutsCheck(),
]

__all__ = ["ALL_CHECKS"]
