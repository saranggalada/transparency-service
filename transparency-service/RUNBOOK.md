# Transparency Service — demo runbook

This walkthrough registers a container image, queries it
back, verifies the receipt with full cryptographic detail, then shows three
denials/failures. Assumes the ledger is already running and bootstrapped
(see `README.md`). Needs Python 3.12+ and Go ≥ 1.22 on `PATH`.

## 0. One-time setup for the shell session

```bash
export SCITT_URL=https://127.0.0.1:8123          # the running ledger
export PATH=$PATH:/usr/local/go/bin              # if go is installed there

# Create the Python venv (once) and install the local pyscitt client.
if [ ! -f venv/bin/activate ]; then
  python3.12 -m venv venv
  source venv/bin/activate
  pip install --disable-pip-version-check --quiet --editable ./pyscitt
else
  source venv/bin/activate
fi

TS=./transparency-service/ts
EX=transparency-service/examples
STORE=transparency-service/identities/service_trust_store/scitt-keys.cbor
ANCH=transparency-service/identities/issuers.json
mkdir -p "$EX"

# Build the offline runtime verifier once.
( cd transparency-service/verify && go build -o ../examples/ts-verify ./cmd/ts-verify )
VERIFY=$EX/ts-verify

# Sample container image + SBOM (stand-ins for a real image tar and SBOM doc).
echo "kserve-controller image layer bytes v1.4.0" > $EX/controller-image.tar
cat > $EX/controller-image.sbom.json <<'JSON'
{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"type":"container","name":"kserve-controller","version":"1.4.0","purl":"pkg:oci/kserve-controller@1.4.0"}]}
JSON
```

## 1. Show the jointly-agreed registration policy

```bash
$TS policy show component
```

Container images must carry a **container digest**, an **SBOM**, and a
**trusted `did:x509` identity** — each with an explicit denial reason.

## 2. Register the image

Show the digests a standard tool computes:

```bash
sha256sum $EX/controller-image.tar $EX/controller-image.sbom.json
```

Sign a statement over the image (records the image digest, the SBOM digest, and
signs under the platform code-signing identity):

```bash
$TS sign-artifact --type component \
  --artifact $EX/controller-image.tar \
  --sbom $EX/controller-image.sbom.json \
  --name kserve-controller --svn 3 \
  --out $EX/controller.sig.cose
```

Submit it to the Transparency Service — **accepted**, returns a `txid` and a
receipt:

```bash
$TS submit-artifact $EX/controller.sig.cose --out $EX/controller.receipt.cose
```

Note the `txid` printed (e.g. `2.17`); use it below.

## 3. Query the record back from the ledger

```bash
$TS query <txid>          # e.g. $TS query 2.17
```

Shows the recorded issuer, container digest, SBOM digest and claims — proof it
is durably recorded and independently auditable.

## 4. Verify the receipt offline, with the real cryptography

This is exactly what the KMS / Controller / Cert-Manager do before deployment.
`--verbose` prints the actual hashes, signatures, and the Merkle root as it is
recomputed, with a `MATCH`/`MISMATCH` at each step:

```bash
$VERIFY --verbose --transparent $EX/controller.receipt.cose \
  --artifact $EX/controller-image.tar \
  --trust-store $STORE --anchors $ANCH
```

## 5. Negative — untrusted identity is DENIED

A statement signed by a rogue CA (valid digest + SBOM, but wrong issuer):

```bash
python3.12 $EX/rogue_submit.py
```

→ `DENIED ... untrusted identity (issuer is not the agreed platform code-signing CA)`.

## 6. Negative — missing SBOM is DENIED

A trusted, correctly-digested image, but with no SBOM claim:

```bash
$TS sign-artifact --type component \
  --artifact $EX/controller-image.tar \
  --name no-sbom --svn 3 --out $EX/nosbom.sig.cose

$TS submit-artifact $EX/nosbom.sig.cose --out /tmp/nosbom.receipt.cose
```

→ `DENIED ... missing required SBOM ('sbom_digest' in payload)`.

## 7. Negative — a tampered receipt FAILS verification

Flip a single byte of the receipt, then verify again:

```bash
cp $EX/controller.receipt.cose $EX/tampered.cose
python3 -c "b=bytearray(open('$EX/tampered.cose','rb').read()); b[-1]^=1; open('$EX/tampered.cose','wb').write(bytes(b))"

$VERIFY --verbose --transparent $EX/tampered.cose \
  --artifact $EX/controller-image.tar \
  --trust-store $STORE --anchors $ANCH
```

→ the signature check prints `MISMATCH [FAIL]` and verification fails.

---

Prefer a scripted walk-through that echoes each command and pauses between
steps? Run `./transparency-service/client-demo.sh` (add `NOPAUSE=1` to run
straight through).
