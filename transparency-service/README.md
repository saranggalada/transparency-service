# Transparency Service

A Transparency Service (TS) for a confidential inferencing platform, built on
[`microsoft/scitt-ccf-ledger`](../README.md) (SCITT on CCF).

The TS registers the artefacts that make up the platform — platform component
images (KServe controller, cert-manager, registry, backend, frontend), AI model
weights, and InferenceGraph definitions — against a per-type policy, **before**
the platform boots. Each successful registration yields a **receipt** (a signed,
Merkle-tree-backed inclusion proof). At runtime, any component can independently
verify that a given artefact digest was registered and satisfied policy, without
trusting the TS operator. Deployment is gated on a valid receipt.

The TS only ever checks **static, signed claims** about an artefact. It never
inspects live attestation — that is the job of the KMS and Certificate Manager at
runtime, which each call the shared verification library here before releasing a
key / issuing a certificate / admitting a graph.

## How it works

```
 Submitter (Inference Provider / Platform Operator)          TS Operator
 ─────────────────────────────────────────────────          ───────────
 ts sign-artifact   ─ sign a COSE statement with a           ts policy show/propose
    did:x509 code-signing key (EKU picks the type)              (per-type Rego)
 ts submit-artifact ─ register ─► [ SCITT CCF ledger ] ◄── set_scitt_configuration
 ts fetch-receipt   ◄─ receipt ─    append-only, Rego
                                    policy per artefact type
 ts validate-artifact ─ local check of the transparent statement

 Runtime (KMS, Cert-Manager, Controller)
 ────────────────────────────────────────
 VerifyArtefact(digest, signedStatement, receipt)  ─ Go library (verify/)
   1. receipt COSE signature   vs pinned TS key
   2. receipt Merkle inclusion vs signed root
   3. statement COSE signature vs did:x509 anchor (pinned)
   4. digest binding           vs the artefact actually loaded
```

**Trust anchor.** Every statement is signed under a `did:x509` issuer whose root
CA fingerprint is embedded in the DID and travels in the COSE `x5chain`. The
artefact *type* is selected by the leaf certificate's EKU. No separate on-ledger
anchor registration is needed: the Rego policy pins the acceptable issuer DIDs,
and the runtime verifier independently re-checks the chain against a pinned
anchor set. Multiple anchors can be trusted at once (add more `allow` rules), so
a CA swap never orphans already-registered artefacts.

## Layout

| Path | What |
|------|------|
| `ts` | The `ts` CLI (submitter + operator verbs). |
| `tscli/` | CLI implementation (thin wrapper over `pyscitt`). |
| `policies/*.rego` | One registration-policy fragment per artefact type. |
| `setup/gen-identities` | Generate demo CAs + per-type signing keys + issuer DIDs. |
| `setup/build_policy.py` | Compose fragments into the merged ledger policy. |
| `setup/bootstrap.sh` | Configure a running ledger as a TS. |
| `verify/` | Go shared runtime verification library + `ts-verify` CLI. |
| `demo.sh` | End-to-end demo of all three artefact types + a rejection. |
| `client-demo.sh` | Guided container-image walkthrough (accept, query, verify, 3 denials). |
| `RUNBOOK.md` | Copy-paste, type-along version of the container-image demo. |

## Prerequisites

- Docker (to run the ledger), Python 3.12, and — for the runtime library — Go ≥ 1.22.
- Run everything from the **repo root**.

## Quickstart

```bash
# 1. Build the ledger image (once; downloads CCF, compiles the app).
./docker/build.sh

# 2. Start a local virtual-mode ledger. If port 8000 is taken, pick another:
CCF_PORT=8123 ./docker/run-dev.sh &        # writes member keys to ./workspace

# 3. Generate demo trust anchors + signing identities.
./transparency-service/setup/gen-identities

# 4. Configure the running ledger as a Transparency Service.
SCITT_URL=https://127.0.0.1:8123 ./transparency-service/setup/bootstrap.sh

# 5. Run the end-to-end demo (register + verify each type, show a rejection).
SCITT_URL=https://127.0.0.1:8123 ./transparency-service/demo.sh
```

## Container-image walkthrough (client demo)

`client-demo.sh` tells the container-image story step by step, pausing between
stages (set `NOPAUSE=1` to run straight through):

```bash
SCITT_URL=https://127.0.0.1:8123 ./transparency-service/client-demo.sh
```

To run each command yourself on camera (instead of via the script), follow the
copy-paste **[`RUNBOOK.md`](./RUNBOOK.md)**. Both use `ts-verify --verbose`,
which prints the actual cryptographic evidence at each step — TBS hashes,
signature `r`/`s`, the Merkle root recomputed leaf→root, cert fingerprints and
EKU — with an explicit `MATCH`/`MISMATCH` per check.

The jointly-agreed policy requires every container image to carry a **container
digest**, an **SBOM**, and a **trusted identity**. The script demonstrates:

1. **Show the policy** — the exact Rego terms enforced for component images.
2. **Register** an image (digest + SBOM + trusted `did:x509` identity) → **accepted**, with a receipt.
3. **Query** the recorded entry back from the ledger by txid.
4. **Verify** the receipt offline with the Go runtime library (the check KMS / Controller / Cert-Manager perform before deployment).
5. **Deny — untrusted identity**: a statement signed by a rogue CA is rejected, reporting the exact unmet term.
6. **Deny — missing SBOM**: a trusted, correctly-digested image without an SBOM claim is rejected.
7. **Tampered receipt**: a single flipped byte makes offline verification fail.

## Start / stop / test

```bash
# START (once): build the ledger image.
./docker/build.sh

# START: run a local virtual-mode ledger (fresh state each time).
CCF_PORT=8123 ./docker/run-dev.sh &

# CONFIGURE it as a Transparency Service (identities + policy + trust store).
./transparency-service/setup/gen-identities
SCITT_URL=https://127.0.0.1:8123 ./transparency-service/setup/bootstrap.sh

# TEST: end-to-end (register + verify each type, plus a policy rejection).
SCITT_URL=https://127.0.0.1:8123 ./transparency-service/demo.sh

# TEST: Go verification library unit tests.
cd transparency-service/verify && go test ./...

# STOP: stop (and, via run-dev.sh's cleanup, remove) the ledger container.
docker ps --filter name=scitt-dev -q | xargs -r docker stop
```

Notes when resuming:
- Virtual-mode state is **not persisted** — restart with `run-dev.sh`, then
  re-run `bootstrap.sh`. Use `CCF_PORT` if `8000` is taken on your host.
- Go isn't a ledger dependency; if the toolchain isn't on `PATH`, use
  `/usr/local/go/bin/go` (installed here) or skip the Go steps.

## CLI (`ts`)

`SCITT_URL` selects the ledger (default `https://127.0.0.1:8000`).

**Submitter / user**

```bash
# Sign a statement for an artefact (digest is computed from the file).
# For container images the policy also requires an SBOM (its digest is recorded).
ts sign-artifact --type component|model|inferencegraph \
   --artifact ./image.tar --sbom ./image.sbom.json --name controller --svn 1 --out st.cose

# Register it and get the transparent statement (statement + receipt).
ts submit-artifact st.cose --out st.receipt.cose

# Query a recorded entry back from the ledger (issuer, digest, SBOM, claims).
ts query 2.42

# Fetch the receipt for an existing ledger transaction id.
ts fetch-receipt 2.42 --out st.receipt.cose

# Locally verify, binding the receipt to a specific artefact.
ts validate-artifact st.receipt.cose --artifact ./image.tar
```

Add arbitrary claims with `--claim key=value` (repeatable); provide a
pre-computed digest with `--digest sha256:<hex>` instead of `--artifact`.

**Operator**

```bash
ts policy show component        # show a policy fragment (issuer resolved)
ts policy show active           # show the merged policy applied to the ledger
ts policy propose model model.rego   # update a fragment and re-propose the policy
ts governance activate-member
ts governance add-member new-member-cert.pem
ts governance constitution
```

Governance member management is intentionally thin (delegates to CCF's native
primitives) until the membership/quorum model is finalized.

## Runtime verification (Go)

The KMS, Certificate Manager and Controller share one library and one entry
point (`verify/verify.go`):

```go
ok, claims, err := verify.VerifyArtefact(digest, signedStatement, receipt, verify.Options{
    TSKeys:         tsKeys,   // pinned once from /.well-known/transparency-configuration
    AllowedAnchors: anchors,  // pinned did:x509 CA fingerprints
})
```

It verifies the receipt signature, the Merkle inclusion proof, the statement's
`did:x509` chain to a pinned anchor, and the digest binding — all offline. Build
the reference CLI and try it against a receipt:

```bash
cd transparency-service/verify && go build -o ../examples/ts-verify ./cmd/ts-verify
transparency-service/examples/ts-verify \
  --transparent st.receipt.cose --artifact ./image.tar \
  --trust-store transparency-service/identities/service_trust_store/scitt-keys.cbor \
  --anchors     transparency-service/identities/issuers.json

# Add --verbose (-v) to print the actual evidence for each of the 4 checks:
#   [1] did:x509 chain to a pinned anchor + leaf EKU
#   [2] signed-statement ECDSA signature (TBS hash, r/s) -> MATCH/MISMATCH
#   [3] receipt: Merkle root recomputed leaf->root + TS signature over it
#   [4] artefact digest binding
```

`go test ./...` covers the DID/digest parsing; the `demo.sh` run exercises the
full cryptographic path against a live ledger.

## Deployment modes

Same application, no code change between them:

- **Virtual (non-TEE)** — for development/testing, as above (`PLATFORM=virtual`,
  single node, `local_development` helper). Do not use its loose auth beyond
  local testing.
- **TEE (AMD SEV-SNP)** — production target: `PLATFORM=snp` build, multi-node
  Raft network, real node attestation (see [`../DEVELOPMENT.md`](../DEVELOPMENT.md)
  → *AMD SEV-SNP platform*). This attests the *TS's own nodes*; it is independent
  of the `did:x509` issuer trust model above.

## Notes on the spec's open questions

Resolved by testing against a live ledger (see spec §9):

1. **Trust-anchor registration** — none needed for `did:x509`; the anchor is the
   CA fingerprint in the issuer, resolved from the `x5chain`. Policies pin the
   issuer(s); multiple anchors are just multiple `allow` rules.
2. **Async registration** — `POST /entries` returns `303 See Other`; the client
   polls `GET /entries/{txid}`. Handled transparently by `ts submit-artifact`.
3. **Rego payload parsing** — the runtime maps a fixed subset of the protected
   header into `input` (`phdr.alg`, `phdr.cty`, and the CWT claims `iss`,
   `sub` = digest, `iat`, `_svn`) and the whole payload as a hex string
   (`input.payload`). Custom header/CWT claims are **not** surfaced. The engine
   **does** support `json.unmarshal(hex.decode(input.payload))`, so payload
   fields can be enforced in-policy — this is how the component policy requires
   the `sbom_digest` claim.
4. **Rego `data` injection** — not relied upon; needed only if ledger-side
   deprecation enforcement is added later (spec §10).

## Known gaps (deliberate, see spec §8, §10)

- Deprecation / minimum-version-floor enforcement is not implemented.
- Governance membership/quorum uses the default constitution + a single member.
- The `did:x509` anchor is an external demo CA; swapping in a real or
  confidential CA changes only the certificates, not the flow.
