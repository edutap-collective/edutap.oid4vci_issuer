"""Where the data in a credential comes from.

Behind a protocol from the start, because this is the part that differs most
between deployments and the part most likely to be replaced: the development
setup reads a file, an installation reads its registry through
``edutap.data_provider``, and neither should be able to see the other.
"""

from pathlib import Path
from typing import Any
from typing import Protocol
from typing import runtime_checkable

import json


@runtime_checkable
class ClaimsSource(Protocol):
    """Supplies the claims for one subject."""

    async def claims_for(self, subject: str) -> dict[str, Any] | None:
        """Return the claims to put into a credential.

        :param subject: whoever the issuer authenticated.
        :returns: the claims, or ``None`` if this subject gets no credential.
            Returning ``None`` rather than raising keeps "not entitled" and
            "something went wrong" apart, which the caller has to answer
            differently.
        """


class FileClaimsSource:
    """Reads claims from a JSON file, for development.

    The file is read on every request rather than cached, so editing it while
    the service runs does what one expects.
    """

    def __init__(self, path: Path) -> None:
        """:param path: JSON object mapping subject to claims."""
        self.path = path

    async def claims_for(self, subject: str) -> dict[str, Any] | None:
        """Return the claims recorded for the subject, if any."""
        if not self.path.exists():
            return None
        with self.path.open(encoding="utf-8") as handle:
            records = json.load(handle)
        claims = records.get(subject)
        return claims if isinstance(claims, dict) else None


class EmptyClaimsSource:
    """Knows nothing about anybody.

    The default when no source is configured. It issues nothing, which is the
    right behaviour for a service that has not been told what to issue -- and
    better than inventing plausible data that would look like a credential.
    """

    async def claims_for(self, subject: str) -> dict[str, Any] | None:
        """Return ``None`` for every subject."""
        return None
