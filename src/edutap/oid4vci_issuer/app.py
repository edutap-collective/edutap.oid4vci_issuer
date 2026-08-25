"""The FastAPI application.

Mounts the protocol endpoints from ``openid4vci`` and adds the one thing that
is ours: a way to start an issuance for someone we have already authenticated.
"""

from .backend import IssuerBackend
from .claims import ClaimsSource
from .claims import EmptyClaimsSource
from .claims import FileClaimsSource
from .settings import Settings
from fastapi import APIRouter
from fastapi import FastAPI
from joserfc.jwk import import_key
from openid4vci.models.offer import offer_uri_by_value
from openid4vci.server_fastapi.app import create_router
from pydantic import BaseModel
from typing import Any

import json


class OfferRequest(BaseModel):
    """Ask the issuer to prepare a credential for someone."""

    subject: str
    tx_code: str | None = None
    tx_code_description: str | None = None


class OfferResponse(BaseModel):
    """What the caller shows the End-User."""

    offer_uri: str
    credential_offer: dict[str, Any]


def load_signing_key(settings: Settings) -> Any:
    """Load the private key that signs issued credentials.

    :raises FileNotFoundError: if the configured key is not there. Failing
        here is deliberate: a service that quietly generated one would issue
        credentials that stop verifying at the next restart.
    """
    if not settings.signing_key_file.exists():
        raise FileNotFoundError(
            f"No signing key at {settings.signing_key_file}. Generate one and "
            "keep it: credentials signed with a different key do not verify, "
            "and nothing in the exchange says why."
        )
    with settings.signing_key_file.open(encoding="utf-8") as handle:
        return import_key(json.load(handle))


def claims_source(settings: Settings) -> ClaimsSource:
    """Return the configured source of credential data."""
    if settings.claims_file is not None:
        return FileClaimsSource(settings.claims_file)
    return EmptyClaimsSource()


def create_app(
    settings: Settings | None = None,
    claims: ClaimsSource | None = None,
) -> FastAPI:
    """Build the application.

    :param settings: configuration. Read from the environment when omitted.
    :param claims: source of credential data, for tests.
    """
    settings = settings or Settings()  # type: ignore[call-arg]
    backend = IssuerBackend(
        settings=settings,
        claims=claims if claims is not None else claims_source(settings),
        signing_key=load_signing_key(settings),
    )

    app = FastAPI(
        title="eduTAP OpenID4VCI Issuer",
        description=(
            "Issues selective-disclosure verifiable credentials to wallets "
            "that speak OpenID4VCI."
        ),
    )
    app.include_router(create_router(backend))

    issuance = APIRouter(tags=["issuance"])

    @issuance.post("/offer", response_model=OfferResponse)
    async def offer(request: OfferRequest) -> OfferResponse:
        """Prepare a credential and return the link that hands it over.

        Authentication is the caller's business, not ours. Whoever calls this
        has already established who the subject is -- a portal login, a desk,
        a federated relying party -- and this endpoint trusts that.
        """
        credential_offer, _code = backend.authorization.offer(
            subject=request.subject,
            credential_configuration_ids=[settings.credential_configuration_id],
            tx_code=request.tx_code,
            tx_code_description=request.tx_code_description,
        )
        return OfferResponse(
            offer_uri=offer_uri_by_value(credential_offer),
            credential_offer=credential_offer.to_dict(),
        )

    @issuance.get("/health")
    async def health() -> dict[str, str]:
        """Report that the service is up and which issuer it speaks for."""
        return {"status": "ok", "credential_issuer": settings.credential_issuer}

    app.include_router(issuance)
    app.state.backend = backend
    return app


def __getattr__(name: str) -> Any:
    """Build the application on first access to ``app``.

    Lazily, so that importing this module reads no configuration and touches
    no key file -- which is what lets the tests import it and build their own
    application with their own settings.
    """
    if name == "app":
        return create_app()
    raise AttributeError(name)
