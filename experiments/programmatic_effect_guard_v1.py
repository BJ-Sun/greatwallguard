"""Compatibility import for the frozen v1 experiment.

The implementation now lives in the installable package.  Keeping this file
means historical experiment commands continue to work without maintaining a
second copy of the algorithm.
"""

from greatwallguard.programmatic_guard import (  # noqa: F401
    GuardDecision as PreCallDecision,
    ProgrammaticAuthorizationGuard as ProgrammaticEffectGuardV1,
)
