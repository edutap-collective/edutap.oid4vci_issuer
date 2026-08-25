# edutap.oid4vci_issuer

**Issues selective-disclosure verifiable credentials over OpenID4VCI.**

The protocol lives in [openid4vci](https://github.com/edutap-eu/OpenID4VCI).
This service supplies what that library deliberately refuses to decide: which
credential a person may receive, where the data comes from, which key signs it,
and how long a challenge stays valid.

> **Pre-alpha.** It issues `dc+sd-jwt` credentials and holds its state in the
> process. Nothing here survives a restart yet.

## What it serves

| Path | Purpose |
| --- | --- |
| `/.well-known/openid-credential-issuer` | metadata a wallet reads first |
| `/nonce` | challenge for a key proof |
| `/credential` | the credential itself |
| `/notification` | what became of it |
| `/offer` | ours: start an issuance for an authenticated subject |
| `/health` | liveness |

`/offer` is the only endpoint that is not protocol. Authentication is the
caller's business: whoever calls it has already established who the subject is.

## Running it

```shell
make key          # once; keep the file
make run
```

The signing key is required rather than generated. A key created at start-up
changes on every restart, and every credential issued before it silently stops
verifying.

## Configuration

Environment, prefixed `EDUTAP_OID4VCI_ISSUER_`:

| Variable | Meaning |
| --- | --- |
| `CREDENTIAL_ISSUER` | our public URL; a wallet appends the well-known path to it |
| `VCT` | credential type a verifier reads first |
| `SIGNING_KEY_FILE` | private JWK that signs credentials |
| `CLAIMS_FILE` | development data: subject to claims, as JSON |
| `CREDENTIAL_CONFIGURATION_ID` | key under which the credential is advertised |
| `DISPLAY_NAME` | name shown while adding the credential |

## License

[EUPL 1.2](https://opensource.org/license/eupl-1-2/)
