#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Client-facing Transparency Service demo (container-image registration).
#
# Storyline:
#   1. Show the jointly-agreed registration policy for container images.
#   2. Register a container image (digest + SBOM + trusted identity) -> ACCEPTED.
#   3. Query the recorded entry back from the ledger.
#   4. Verify the receipt offline (what KMS / Controller / Cert-Manager do).
#   5. Negative case A: untrusted identity -> DENIED.
#   6. Negative case B: missing SBOM claim -> DENIED.
#   7. Negative case C: tampered receipt -> verification FAILS.
#
# Prereqs: ledger running + bootstrapped. Honours SCITT_URL (default :8000).

set -uo pipefail

TS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$TS_DIR/.." && pwd)"
cd "$REPO_ROOT"

# If SCITT_URL is not set, auto-detect the ledger on common local ports.
if [ -z "${SCITT_URL:-}" ]; then
    for port in 8000 8123; do
        if curl -sk --max-time 3 "https://127.0.0.1:$port/node/network" >/dev/null; then
            SCITT_URL="https://127.0.0.1:$port"; break
        fi
    done
    SCITT_URL="${SCITT_URL:-https://127.0.0.1:8000}"
fi
export SCITT_URL
# Keep the demo output clean; the CLI prints its own human-readable results.
export LOGURU_LEVEL="${LOGURU_LEVEL:-CRITICAL}"
TS="$TS_DIR/ts"
EX="$TS_DIR/examples"
STORE="$TS_DIR/identities/service_trust_store/scitt-keys.cbor"
ANCHORS="$TS_DIR/identities/issuers.json"
GO_BIN="$(command -v go || echo /usr/local/go/bin/go)"
mkdir -p "$EX"

banner() { echo; echo "========================================================"; echo "# $1"; echo "========================================================"; }
pause()  { [ -n "${NOPAUSE:-}" ] || { echo; read -rp "  (press Enter to continue) " _; }; }
die()    { echo; echo "ERROR: $1" >&2; exit 1; }
# run echoes the exact command (as if typed) and then executes it, so viewers
# see precisely what was run and the real output it produced.
run()    { echo; echo "\$ $*"; echo; "$@"; }

# Preflight: fail loudly if the Transparency Service is not reachable, rather
# than silently talking to the wrong port during a live recording.
if ! curl -sk --max-time 5 "$SCITT_URL/node/network" >/dev/null; then
    die "Transparency Service not reachable at $SCITT_URL
     Start it and point the demo at the right port, e.g.:
       CCF_PORT=8123 ./docker/run-dev.sh &
       SCITT_URL=https://127.0.0.1:8123 ./transparency-service/setup/bootstrap.sh
       SCITT_URL=https://127.0.0.1:8123 $0"
fi
echo "Transparency Service reachable at $SCITT_URL"

# Build the Go runtime verifier.
( cd "$TS_DIR/verify" && "$GO_BIN" build -o "$EX/ts-verify" ./cmd/ts-verify )
VERIFY="$EX/ts-verify"

# Sample container image + SBOM (stand-ins for a real image tar + SBOM doc).
echo "kserve-controller image layer bytes v1.4.0" > "$EX/controller-image.tar"
cat > "$EX/controller-image.sbom.json" <<'JSON'
{"bomFormat":"CycloneDX","specVersion":"1.5",
 "components":[{"type":"container","name":"kserve-controller","version":"1.4.0",
 "purl":"pkg:oci/kserve-controller@1.4.0"}]}
JSON

banner "1. The jointly-agreed registration policy for container images"
run "$TS" policy show component
pause

banner "2a. The artefact + SBOM, and their digests (computed by sha256sum)"
run sha256sum "$EX/controller-image.tar" "$EX/controller-image.sbom.json"
pause

banner "2b. Sign a statement over the image (records digest + SBOM + identity)"
run "$TS" sign-artifact --type component \
    --artifact "$EX/controller-image.tar" \
    --sbom "$EX/controller-image.sbom.json" \
    --name kserve-controller --svn 3 \
    --out "$EX/controller.sig.cose"
pause

banner "2c. Register it with the Transparency Service -> ACCEPTED, get a receipt"
rm -f "$EX/controller.receipt.cose"
echo; echo "\$ $TS submit-artifact $EX/controller.sig.cose --out $EX/controller.receipt.cose"; echo
OUT="$("$TS" submit-artifact "$EX/controller.sig.cose" --out "$EX/controller.receipt.cose" 2>&1)"
echo "$OUT"
TXID="$(echo "$OUT" | awk '/txid:/{print $2}')"
[ -n "$TXID" ] && [ -f "$EX/controller.receipt.cose" ] || \
    die "registration did not return a txid (see message above); aborting demo."
pause

banner "3. Query the recorded entry back from the ledger (txid $TXID)"
run "$TS" query "$TXID"
pause

banner "4. Verify the receipt offline, showing the actual cryptography"
run "$VERIFY" --verbose --transparent "$EX/controller.receipt.cose" \
    --artifact "$EX/controller-image.tar" \
    --trust-store "$STORE" --anchors "$ANCHORS"
pause

banner "5. Negative A: untrusted identity -> must be DENIED by policy"
# shellcheck disable=SC1091
source venv/bin/activate
run python3.12 "$EX/rogue_submit.py"
pause

banner "6. Negative B: missing SBOM claim -> must be DENIED by policy"
run "$TS" sign-artifact --type component \
    --artifact "$EX/controller-image.tar" \
    --name kserve-controller-no-sbom --svn 3 \
    --out "$EX/nosbom.sig.cose"
echo; echo "\$ $TS submit-artifact $EX/nosbom.sig.cose --out /tmp/nosbom.receipt.cose"; echo
if "$TS" submit-artifact "$EX/nosbom.sig.cose" --out /tmp/nosbom.receipt.cose; then
    echo "UNEXPECTED: accepted"
fi
pause

banner "7. Negative C: tamper one byte of the receipt -> verification FAILS"
run cp "$EX/controller.receipt.cose" "$EX/tampered.cose"
echo; echo "\$ python3 -c 'flip the last byte of tampered.cose'"; echo
python3.12 -c "b=bytearray(open('$EX/tampered.cose','rb').read()); b[-1]^=1; open('$EX/tampered.cose','wb').write(bytes(b))"
run "$VERIFY" --verbose --transparent "$EX/tampered.cose" \
    --artifact "$EX/controller-image.tar" \
    --trust-store "$STORE" --anchors "$ANCHORS" || true

echo; echo "Demo complete."
