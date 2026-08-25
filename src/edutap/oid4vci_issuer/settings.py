"""Configuration, from the environment.

Twelve-factor: everything that differs between deployments arrives prefixed
with ``EDUTAP_OID4VCI_ISSUER_``. Nothing is read from a checked-in file.
"""

from pathlib import Path
from pydantic import Field
from pydantic_settings import BaseSettings
from pydantic_settings import SettingsConfigDict


ENV_PREFIX = "EDUTAP_OID4VCI_ISSUER_"


class Settings(BaseSettings):
    """Settings of the issuer service."""

    model_config = SettingsConfigDict(
        env_prefix=ENV_PREFIX,
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    credential_issuer: str = Field(
        description=(
            "Our Credential Issuer Identifier. A wallet appends "
            "/.well-known/openid-credential-issuer to it, so it must be the "
            "public URL rather than an internal one."
        ),
    )

    credential_configuration_id: str = Field(
        default="StudentCredential",
        description="Key under which this credential is advertised in the metadata.",
    )

    vct: str = Field(description="The credential type a verifier reads first.")

    signing_key_file: Path = Field(
        description=(
            "Private JWK that signs issued credentials. Required rather than "
            "generated: a key created at start-up changes on every restart, "
            "and every credential issued before it becomes unverifiable "
            "without anything saying so."
        ),
    )

    display_name: str = Field(
        default="eduTAP Issuer",
        description="Name shown to the holder while adding the credential.",
    )

    claims_file: Path | None = Field(
        default=None,
        description=(
            "Development data source: a JSON object mapping a subject to its "
            "claims. Left unset, the issuer has nothing to issue and says so."
        ),
    )

    nonce_ttl_seconds: int = Field(default=300, gt=0)
    code_ttl_seconds: int = Field(default=600, gt=0)
    token_ttl_seconds: int = Field(default=3600, gt=0)
