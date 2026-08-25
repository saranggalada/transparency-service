#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Configure a *running* SCITT CCF ledger as a Transparency Service:
#   1. generate demo identities (if missing)
#   2. build the merged registration policy
#   3. propose it via set_scitt_configuration
#   4. save the service's signing keys to a local trust store (for verification)
#
# Prerequisites: the ledger is already running and open, with member keys in
# ./workspace (this is what `docker/run-dev.sh` produces).

set -euo pipefail

TS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$TS_DIR/.." && pwd)"
cd "$REPO_ROOT"

SCITT_URL="${SCITT_URL:-https://127.0.0.1:8000}"
MEMBER_KEY="${TS_MEMBER_KEY:-workspace/member0_privk.pem}"
MEMBER_CERT="${TS_MEMBER_CERT:-workspace/member0_cert.pem}"
IDENTITIES_DIR="$TS_DIR/identities"
TRUST_STORE="$IDENTITIES_DIR/service_trust_store"

if [ ! -f "venv/bin/activate" ]; then
    python3.12 -m venv venv
    # shellcheck disable=SC1091
    source venv/bin/activate
    pip install --disable-pip-version-check --quiet --editable ./pyscitt
else
    # shellcheck disable=SC1091
    source venv/bin/activate
fi
export PYTHONPATH="$TS_DIR:${PYTHONPATH:-}"

echo "== Generating identities (if needed) =="
python3.12 "$TS_DIR/setup/gen_identities.py" || true

echo "== Building merged policy =="
python3.12 "$TS_DIR/setup/build_policy.py"

echo "== Proposing Transparency Service configuration =="
scitt governance propose_configuration \
    --url "$SCITT_URL" \
    --member-key "$MEMBER_KEY" \
    --member-cert "$MEMBER_CERT" \
    --configuration "$IDENTITIES_DIR/configuration.json" \
    --development

echo "== Saving service trust store to $TRUST_STORE =="
mkdir -p "$TRUST_STORE"
curl -k -f "$SCITT_URL/.well-known/scitt-keys" -o "$TRUST_STORE/scitt-keys.cbor"

echo ""
echo "Transparency Service is configured and ready at $SCITT_URL"
