#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# End-to-end Transparency Service demo: register one artefact of each type,
# verify each with the Python CLI and the Go runtime library, and show that an
# untrusted artefact is rejected by policy.
#
# Prereqs: ledger running + bootstrapped (see transparency-service/README.md).
# Honours SCITT_URL (default https://127.0.0.1:8000).

set -euo pipefail

TS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$TS_DIR/.." && pwd)"
cd "$REPO_ROOT"

SCITT_URL="${SCITT_URL:-https://127.0.0.1:8000}"
export SCITT_URL
TS="$TS_DIR/ts"
EX="$TS_DIR/examples"
TRUST_STORE="$TS_DIR/identities/service_trust_store/scitt-keys.cbor"
ANCHORS="$TS_DIR/identities/issuers.json"
mkdir -p "$EX"

# Build the Go verifier if the Go toolchain is available.
GO_BIN="$(command -v go || echo /usr/local/go/bin/go)"
TS_VERIFY=""
if [ -x "$GO_BIN" ]; then
    ( cd "$TS_DIR/verify" && "$GO_BIN" build -o "$EX/ts-verify" ./cmd/ts-verify )
    TS_VERIFY="$EX/ts-verify"
fi

# Sample artefacts (stand-ins for a real image tar / weights / graph yaml).
echo "kserve-controller image bytes v1.2.3" > "$EX/controller-image.txt"
echo '{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"name":"kserve-controller"}]}' > "$EX/controller.sbom.json"
echo "SAFE-TENSORS model weights for llama-3-8b" > "$EX/llama3-weights.safetensors"
cat > "$EX/llm-graph.yaml" <<'YAML'
apiVersion: serving.kserve.io/v1alpha1
kind: InferenceGraph
metadata: {name: llm-graph}
spec: {nodes: {root: {steps: [{serviceName: llama}]}}}
YAML

register() {
    local type="$1" artifact="$2" name="$3" sbom="${4:-}"
    echo ""
    echo "############################################################"
    echo "# Registering $type: $name"
    echo "############################################################"
    local sbom_args=()
    [ -n "$sbom" ] && sbom_args=(--sbom "$sbom")
    "$TS" sign-artifact --type "$type" --artifact "$artifact" --name "$name" --svn 1 \
        "${sbom_args[@]}" --out "$EX/$name.sig.cose"
    "$TS" submit-artifact "$EX/$name.sig.cose" --out "$EX/$name.receipt.cose" 2>&1 | grep -v DEBUG || true
    echo "--- Python validation (with digest binding) ---"
    "$TS" validate-artifact "$EX/$name.receipt.cose" --artifact "$artifact" 2>&1 | grep -v DEBUG || true
    if [ -n "$TS_VERIFY" ]; then
        echo "--- Go runtime verification (what KMS/Controller/Cert-Manager run) ---"
        "$TS_VERIFY" --transparent "$EX/$name.receipt.cose" --artifact "$artifact" \
            --trust-store "$TRUST_STORE" --anchors "$ANCHORS"
    fi
}

register component      "$EX/controller-image.txt"        controller "$EX/controller.sbom.json"
register model          "$EX/llama3-weights.safetensors"  llama3
register inferencegraph "$EX/llm-graph.yaml"              llm-graph

echo ""
echo "############################################################"
echo "# Negative case: untrusted CA must be rejected by policy"
echo "############################################################"
# shellcheck disable=SC1091
source venv/bin/activate
python3.12 "$EX/rogue_submit.py"

echo ""
echo "Demo complete."
