.PHONY: help lint reformat typecheck test-local run key

help:  ## show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-16s %s\n", $$1, $$2}'

lint:  ## run all linters
	uvx prek run --all-files

reformat:  ## autoformat the code
	uvx ruff format src tests
	uvx ruff check --fix src tests

typecheck:  ## run the type checker
	uv run --group typecheck --group test ty check

test-local:  ## run the unit tests
	uv run --group test pytest

run:  ## serve the issuer locally
	uv run uvicorn edutap.oid4vci_issuer.app:app --reload --port 8000

key:  ## generate a signing key, once
	@test -f issuer-key.json || uv run python -c "\
from joserfc.jwk import ECKey; import json, pathlib; \
k = ECKey.generate_key('P-256', auto_kid=True); \
pathlib.Path('issuer-key.json').write_text(json.dumps(k.as_dict(private=True), indent=2)); \
print('wrote issuer-key.json -- keep it, credentials signed with another key do not verify')"
	@test -f issuer-key.json && echo "issuer-key.json is there"
