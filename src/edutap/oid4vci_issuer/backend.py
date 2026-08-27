"""The decisions the protocol library refuses to make.

``openid4vci`` implements the exchange and leaves five questions open: what we
publish, which challenge is current, whether an access token grants anything,
what goes into the credential, and what became of it. This module answers
them, and that is the whole reason the service exists.
"""

from .claims import ClaimsSource
from .settings import Settings
from openid4vci.adapters.sd_jwt_vc import FORMAT_SD_JWT_VC
from openid4vci.adapters.sd_jwt_vc import SdJwtVcAdapter
from openid4vci.authorization import InMemoryAuthorizationServer
from openid4vci.crypto.proofs import validate_jwt_proof
from openid4vci.crypto.signer import LocalJwsSigner
from openid4vci.exceptions import CredentialRequestError
from openid4vci.models.credential import CredentialErrorCode
from openid4vci.models.credential import CredentialRequest
from openid4vci.models.credential import CredentialResponse
from openid4vci.models.deferred import DeferredCredentialRequest
from openid4vci.models.metadata import CredentialIssuerMetadata
from openid4vci.models.notification import NotificationRequest
from openid4vci.reference import InMemoryNonceStore
from openid4vci.server_fastapi.app import RequestContext
from typing import Any

import base64
import json


#: Signature algorithm we issue with, and the only one we accept in a proof.
SIGNING_ALGORITHM = "ES256"


class IssuerBackend:
    """Wires the protocol library to this deployment's answers."""

    def __init__(
        self,
        settings: Settings,
        claims: ClaimsSource,
        signing_key: Any,
    ) -> None:
        """Wire the library to this deployment.

        :param settings: configuration from the environment.
        :param claims: where credential data comes from.
        :param signing_key: private key that signs issued credentials.
        """
        self.settings = settings
        self.claims = claims
        self.authorization = InMemoryAuthorizationServer(
            credential_issuer=settings.credential_issuer,
            code_ttl_seconds=settings.code_ttl_seconds,
            token_ttl_seconds=settings.token_ttl_seconds,
        )
        self.nonces = InMemoryNonceStore(ttl_seconds=settings.nonce_ttl_seconds)
        self.adapter = SdJwtVcAdapter(
            vct=settings.vct,
            signer=LocalJwsSigner(signing_key, algorithm=SIGNING_ALGORITHM),
            issuer=settings.credential_issuer,
        )
        self.notifications: list[NotificationRequest] = []

    async def issuer_metadata(self) -> CredentialIssuerMetadata:
        """Return what a wallet reads before it asks for anything.

        The credential is key bound, so the metadata says so in both places the
        specification ties together: a binding method and the proof types that
        go with it.
        """
        settings = self.settings
        # The endpoints are advertised as absolute URLs, so they need not sit
        # under the identifier -- and usually should not, because the
        # identifier only fixes where /.well-known/openid-credential-issuer
        # is looked for.
        base = (settings.endpoint_base_url or settings.credential_issuer).rstrip("/")
        return CredentialIssuerMetadata.model_validate(
            {
                "credential_issuer": settings.credential_issuer,
                "credential_endpoint": f"{base}/credential",
                "nonce_endpoint": f"{base}/nonce",
                "notification_endpoint": f"{base}/notification",
                "display": [{"name": settings.display_name, "locale": "en-US"}],
                "credential_configurations_supported": {
                    settings.credential_configuration_id: {
                        "format": FORMAT_SD_JWT_VC,
                        "scope": settings.credential_configuration_id,
                        "vct": settings.vct,
                        "cryptographic_binding_methods_supported": ["jwk"],
                        "credential_signing_alg_values_supported": [SIGNING_ALGORITHM],
                        "proof_types_supported": {
                            "jwt": {
                                "proof_signing_alg_values_supported": [
                                    SIGNING_ALGORITHM
                                ]
                            }
                        },
                    }
                },
            }
        )

    async def create_nonce(self) -> str:
        """Return a fresh challenge."""
        return self.nonces.issue()

    async def issue_credential(
        self, request: CredentialRequest, context: RequestContext
    ) -> CredentialResponse:
        """Issue, or refuse with the code that says why."""
        grant = self.authorization.grant_for(context.access_token)
        if grant is None:
            raise CredentialRequestError(
                CredentialErrorCode.CREDENTIAL_REQUEST_DENIED,
                "The access token is unknown to this issuer, or has expired",
            )

        configuration_id = self.settings.credential_configuration_id
        if request.credential_configuration_id not in (None, configuration_id):
            raise CredentialRequestError(
                CredentialErrorCode.UNKNOWN_CREDENTIAL_CONFIGURATION,
                f"This issuer offers {configuration_id!r} only",
            )

        proofs = (request.proofs or {}).get("jwt") or []
        if not proofs:
            raise CredentialRequestError(
                CredentialErrorCode.INVALID_PROOF,
                "This credential is bound to a key, so a key proof is required",
            )

        result = validate_jwt_proof(
            proofs[0],
            credential_issuer=self.settings.credential_issuer,
            c_nonce=self._spend_nonce(proofs[0]),
            supported_algorithms=[SIGNING_ALGORITHM],
        )

        claims = await self.claims.claims_for(grant.subject)
        if claims is None:
            # Not an error in the request: the request was fine, this person
            # simply has nothing to receive. The specification has a code for
            # exactly that, and it tells the wallet not to retry.
            raise CredentialRequestError(
                CredentialErrorCode.CREDENTIAL_REQUEST_DENIED,
                "This issuer holds no credential for you",
            )

        credential = await self.adapter.issue(claims, holder_key=result.bound_key)
        return CredentialResponse.model_validate(
            {"credentials": [{"credential": credential}]}
        )

    async def issue_deferred(
        self, request: DeferredCredentialRequest, context: RequestContext
    ) -> CredentialResponse:
        """Not offered: this issuer answers immediately or not at all."""
        raise NotImplementedError(
            "This issuer does not defer; its metadata advertises no deferred endpoint"
        )

    async def notify(
        self, request: NotificationRequest, context: RequestContext
    ) -> None:
        """Record what became of an issued credential."""
        self.notifications.append(request)

    def _spend_nonce(self, proof: str) -> str:
        """Consume the challenge a proof carries.

        Spent before the signature is checked, so a malformed proof burns it
        too. That is the safe direction: the alternative lets someone probe
        signatures against one challenge indefinitely, and a wallet recovers
        from this one because invalid_nonce is precisely the error that tells
        it to fetch another.
        """
        payload = proof.split(".")[1] if proof.count(".") == 2 else ""
        try:
            padded = payload + "=" * (-len(payload) % 4)
            presented = json.loads(base64.urlsafe_b64decode(padded)).get("nonce")
        except (ValueError, IndexError):
            presented = None
        if presented is None or not self.nonces.consume(presented):
            raise CredentialRequestError(
                CredentialErrorCode.INVALID_NONCE,
                "Fetch a fresh challenge from the nonce endpoint and try again",
            )
        return presented
