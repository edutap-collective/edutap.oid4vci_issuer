"""The service, end to end.

Offer, token, nonce, key proof, credential -- the exchange a wallet performs,
against the application this service actually serves.
"""

from edutap.oid4vci_issuer.app import create_app
from edutap.oid4vci_issuer.claims import EmptyClaimsSource
from edutap.oid4vci_issuer.settings import Settings
from fastapi.testclient import TestClient
from joserfc import jwt
from joserfc.jwk import ECKey
from openid4vci.models.common import GRANT_TYPE_PRE_AUTHORIZED_CODE
from openid4vci.models.oauth import TokenRequest

import base64
import json
import pytest


ISSUER = "https://issuer.example.edu"
VCT = "https://credentials.example.edu/student"

CLAIMS = {"erika": {"given_name": "Erika", "matriculation_number": "12345678"}}


class DictClaims:
    """A claims source backed by a dict, so tests need no files."""

    def __init__(self, records):
        self.records = records

    async def claims_for(self, subject):
        return self.records.get(subject)


@pytest.fixture
def key_file(tmp_path):
    key = ECKey.generate_key("P-256", auto_kid=True)
    path = tmp_path / "issuer-key.json"
    path.write_text(json.dumps(key.as_dict(private=True)), encoding="utf-8")
    return path, key


@pytest.fixture
def settings(key_file):
    path, _ = key_file
    return Settings(
        _env_file=None,
        credential_issuer=ISSUER,
        vct=VCT,
        signing_key_file=path,
    )


@pytest.fixture
def app(settings):
    return create_app(settings=settings, claims=DictClaims(CLAIMS))


@pytest.fixture
def client(app):
    return TestClient(app)


def token_for(app, subject="erika"):
    """Walk the offer and the token endpoint the way a wallet would."""
    backend = app.state.backend
    _offer, code = backend.authorization.offer(
        subject=subject,
        credential_configuration_ids=[backend.settings.credential_configuration_id],
    )
    return backend.authorization.redeem(
        TokenRequest.model_validate(
            {
                "grant_type": GRANT_TYPE_PRE_AUTHORIZED_CODE,
                "pre-authorized_code": code,
            }
        )
    )


def wallet_proof(holder_key, nonce):
    return jwt.encode(
        {
            "typ": "openid4vci-proof+jwt",
            "alg": "ES256",
            "jwk": holder_key.as_dict(private=False),
        },
        {"aud": ISSUER, "iat": 1_766_000_000, "nonce": nonce},
        holder_key,
    )


def test_the_service_reports_which_issuer_it_speaks_for(client):
    body = client.get("/health").json()

    assert body == {"status": "ok", "credential_issuer": ISSUER}


def test_the_metadata_says_the_credential_is_key_bound(client):
    metadata = client.get("/.well-known/openid-credential-issuer").json()

    assert metadata["credential_issuer"] == ISSUER
    configuration = metadata["credential_configurations_supported"]["StudentCredential"]
    assert configuration["format"] == "dc+sd-jwt"
    assert configuration["vct"] == VCT
    # Both halves, because the specification ties them to each other.
    assert configuration["cryptographic_binding_methods_supported"] == ["jwk"]
    assert "jwt" in configuration["proof_types_supported"]


def test_an_offer_comes_back_as_a_link_a_wallet_understands(client):
    body = client.post("/offer", json={"subject": "erika"}).json()

    assert body["offer_uri"].startswith("openid-credential-offer://?")
    assert body["credential_offer"]["credential_issuer"] == ISSUER


def test_an_offer_can_demand_a_transaction_code(client):
    body = client.post(
        "/offer",
        json={
            "subject": "erika",
            "tx_code": "493536",
            "tx_code_description": "Sent to your university address",
        },
    ).json()

    grant = body["credential_offer"]["grants"][GRANT_TYPE_PRE_AUTHORIZED_CODE]
    assert grant["tx_code"]["length"] == 6
    assert "493536" not in json.dumps(body), (
        "the offer describes the code, never carries it"
    )


def test_a_credential_is_issued_and_bound_to_the_wallet_key(client, app, key_file):
    _, issuer_key = key_file
    token = token_for(app)
    nonce = client.post("/nonce").json()["c_nonce"]
    holder_key = ECKey.generate_key("P-256")

    response = client.post(
        "/credential",
        json={
            "credential_configuration_id": "StudentCredential",
            "proofs": {"jwt": [wallet_proof(holder_key, nonce)]},
        },
        headers={"Authorization": f"Bearer {token.access_token}"},
    )

    assert response.status_code == 200
    credential = response.json()["credentials"][0]["credential"]

    from joserfc import jws

    issuer_jwt, *disclosures, key_binding = credential.split("~")
    assert key_binding == ""
    payload = json.loads(jws.deserialize_compact(issuer_jwt, issuer_key).payload)

    assert payload["vct"] == VCT
    assert payload["iss"] == ISSUER
    assert payload["cnf"]["jwk"] == holder_key.as_dict(private=False)
    # The data is disclosable, so none of it stands in the payload.
    assert "12345678" not in json.dumps(payload)

    disclosed = {}
    for disclosure in disclosures:
        padded = disclosure + "=" * (-len(disclosure) % 4)
        _, name, value = json.loads(base64.urlsafe_b64decode(padded))
        disclosed[name] = value
    assert disclosed == CLAIMS["erika"]


def test_a_replayed_proof_is_refused(client, app):
    token = token_for(app)
    nonce = client.post("/nonce").json()["c_nonce"]
    holder_key = ECKey.generate_key("P-256")
    body = {
        "credential_configuration_id": "StudentCredential",
        "proofs": {"jwt": [wallet_proof(holder_key, nonce)]},
    }
    headers = {"Authorization": f"Bearer {token.access_token}"}

    assert client.post("/credential", json=body, headers=headers).status_code == 200

    again = client.post("/credential", json=body, headers=headers)
    assert again.status_code == 400
    assert again.json()["error"] == "invalid_nonce"


def test_someone_we_hold_nothing_for_is_told_so(client, app):
    """Not an error in the request -- the request was fine."""
    token = token_for(app, subject="unknown-person")
    nonce = client.post("/nonce").json()["c_nonce"]
    holder_key = ECKey.generate_key("P-256")

    response = client.post(
        "/credential",
        json={
            "credential_configuration_id": "StudentCredential",
            "proofs": {"jwt": [wallet_proof(holder_key, nonce)]},
        },
        headers={"Authorization": f"Bearer {token.access_token}"},
    )

    assert response.status_code == 400
    assert response.json()["error"] == "credential_request_denied"


def test_an_unknown_configuration_is_refused(client, app):
    token = token_for(app)
    nonce = client.post("/nonce").json()["c_nonce"]
    holder_key = ECKey.generate_key("P-256")

    response = client.post(
        "/credential",
        json={
            "credential_configuration_id": "SomethingElse",
            "proofs": {"jwt": [wallet_proof(holder_key, nonce)]},
        },
        headers={"Authorization": f"Bearer {token.access_token}"},
    )

    assert response.json()["error"] == "unknown_credential_configuration"


def test_a_missing_signing_key_fails_loudly(tmp_path):
    """Better than generating one: a fresh key invalidates every credential."""
    settings = Settings(
        _env_file=None,
        credential_issuer=ISSUER,
        vct=VCT,
        signing_key_file=tmp_path / "absent.json",
    )

    with pytest.raises(FileNotFoundError, match="do not verify"):
        create_app(settings=settings, claims=EmptyClaimsSource())


def test_the_endpoints_sit_under_the_identifier_by_default(client):
    metadata = client.get("/.well-known/openid-credential-issuer").json()

    assert metadata["credential_endpoint"] == f"{ISSUER}/credential"


def test_the_endpoints_can_live_somewhere_else_entirely(key_file):
    """Only the metadata location derives from the identifier.

    The identifier fixes where /.well-known/openid-credential-issuer is looked
    for, and that path is shared with OIDC discovery, federation metadata, app
    association files and ACME challenges. A deployment therefore maps one
    exact path there and puts the endpoints under a prefix of its own.
    """
    path, _ = key_file
    settings = Settings(
        _env_file=None,
        credential_issuer="https://login.example.edu",
        endpoint_base_url="https://login.example.edu/public-api/wallet/oid4vci/v1",
        vct=VCT,
        signing_key_file=path,
    )
    client = TestClient(create_app(settings=settings, claims=DictClaims(CLAIMS)))

    metadata = client.get("/.well-known/openid-credential-issuer").json()

    assert metadata["credential_issuer"] == "https://login.example.edu"
    assert metadata["credential_endpoint"] == (
        "https://login.example.edu/public-api/wallet/oid4vci/v1/credential"
    )
    assert metadata["nonce_endpoint"].endswith("/oid4vci/v1/nonce")


def test_a_trailing_slash_on_the_base_url_does_not_double(key_file):
    path, _ = key_file
    settings = Settings(
        _env_file=None,
        credential_issuer="https://login.example.edu",
        endpoint_base_url="https://login.example.edu/oid4vci/",
        vct=VCT,
        signing_key_file=path,
    )
    client = TestClient(create_app(settings=settings, claims=DictClaims(CLAIMS)))

    metadata = client.get("/.well-known/openid-credential-issuer").json()

    assert (
        metadata["credential_endpoint"]
        == "https://login.example.edu/oid4vci/credential"
    )
