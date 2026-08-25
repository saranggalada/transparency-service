# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Submitter/user verbs: sign, submit, fetch-receipt, validate."""

import hashlib
import json
import sys
from pathlib import Path

from pyscitt import crypto
from pyscitt.client import Client, ServiceError
from pyscitt.crypto import Signer
from pycose.headers import ContentType
from pyscitt.verify import (
    DynamicTrustStore,
    StaticTrustStore,
    verify_transparent_statement,
)
from pycose.messages import Sign1Message

from .constants import ARTEFACT_TYPES
from .config import Config


def _digest_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return "sha256:" + h.hexdigest()


def _load_x5c(path: Path):
    data = path.read_bytes()
    certs, rest = [], data
    while rest:
        pem, _, rest = rest.partition(b"-----END CERTIFICATE-----\n")
        pem += b"-----END CERTIFICATE-----\n"
        if b"BEGIN CERTIFICATE" in pem:
            certs.append(pem.decode())
    return certs


def sign_artifact(args):
    cfg = Config()
    spec = ARTEFACT_TYPES[args.type]
    issuers = cfg.issuers()["issuers"]
    issuer = issuers[args.type]

    if args.digest:
        digest = args.digest if ":" in args.digest else "sha256:" + args.digest
    elif args.artifact:
        digest = _digest_file(Path(args.artifact))
    else:
        raise SystemExit("Provide either --artifact <path> or --digest <hex>.")

    claims = {
        "name": args.name or (Path(args.artifact).name if args.artifact else digest),
        "artifact_type": args.type,
        "digest": digest,
    }
    if getattr(args, "sbom", None):
        sbom_path = Path(args.sbom)
        claims["sbom_digest"] = _digest_file(sbom_path)
        claims["sbom_name"] = sbom_path.name
    for kv in args.claim or []:
        k, _, v = kv.partition("=")
        claims[k] = v
    payload = json.dumps(claims, sort_keys=True).encode()

    key = crypto.load_private_key(cfg.identities_dir / f"{args.type}_key.pem")
    x5c = _load_x5c(cfg.identities_dir / f"{args.type}_x5c.pem")
    signer = Signer(key, issuer=issuer, x5c=x5c)

    signed = crypto.sign_statement(
        signer,
        payload,
        content_type=spec["content_type"],
        feed=digest,  # CWT 'sub' = the artefact digest (checked by policy + verifier)
        svn=args.svn,
        cwt=True,
    )
    Path(args.out).write_bytes(signed)
    print(f"Signed {args.type} statement for {digest}")
    print(f"  issuer: {issuer}")
    if claims.get("sbom_digest"):
        print(f"  sbom:   {claims['sbom_digest']} ({claims.get('sbom_name')})")
    print(f"  wrote:  {args.out}")


def submit_artifact(args):
    cfg = Config()
    client = Client(cfg.url, development=cfg.development)
    signed = Path(args.statement).read_bytes()
    try:
        submission = client.submit_signed_statement_and_wait(signed)
    except ServiceError as e:
        print(f"DENIED by registration policy: {e.message}", file=sys.stderr)
        sys.exit(2)
    Path(args.out).write_bytes(submission.response_bytes)
    print("Registered with the Transparency Service.")
    print(f"  txid:  {submission.tx}")
    print(f"  seqno: {submission.seqno}")
    print(f"  transparent statement (statement + receipt): {args.out}")


def fetch_receipt(args):
    cfg = Config()
    client = Client(cfg.url, development=cfg.development)
    statement = client.get_transparent_statement(args.txid)
    Path(args.out).write_bytes(statement)
    print(f"Wrote transparent statement for {args.txid} to {args.out}")


def query(args):
    """Query a recorded entry from the ledger by txid and print its claims.

    Demonstrates that the statement is durably recorded and auditable by anyone.
    """
    cfg = Config()
    client = Client(cfg.url, development=cfg.development)
    ts_bytes = client.get_transparent_statement(args.txid)
    if args.out:
        Path(args.out).write_bytes(ts_bytes)

    msg = Sign1Message.decode(ts_bytes)
    cwt = msg.phdr.get(crypto.CWTClaims, {})
    payload = {}
    if msg.payload:
        try:
            payload = json.loads(msg.payload)
        except Exception:
            payload = {}
    cty = msg.phdr.get(ContentType)
    has_receipt = bool(msg.uhdr.get(crypto.SCITTReceipts))
    print(f"Ledger record {args.txid} (recorded and receipted: {has_receipt})")
    print(f"  issuer (identity): {cwt.get(crypto.CWT_ISS)}")
    print(f"  content-type:      {cty}")
    print(f"  container digest:  {cwt.get(crypto.CWT_SUB)}")
    if payload.get("sbom_digest"):
        print(f"  sbom digest:       {payload['sbom_digest']} ({payload.get('sbom_name')})")
    print(f"  recorded claims:   {json.dumps(payload, sort_keys=True)}")


def validate_artifact(args):
    cfg = Config()
    ts_bytes = Path(args.statement).read_bytes()

    # Strip the receipt(s) from the unprotected header to recover the exact
    # signed statement the receipt commits to.
    msg = Sign1Message.decode(ts_bytes)
    msg.uhdr = {}
    signed_statement = msg.encode(tag=True, sign=False)

    trust_store_dir = Path(args.trust_store) if args.trust_store else cfg.trust_store_dir
    if trust_store_dir.exists():
        store = StaticTrustStore.load(trust_store_dir)
    else:
        store = DynamicTrustStore()

    details = verify_transparent_statement(ts_bytes, store, signed_statement)
    print("Receipt is valid: statement is on the Transparency Service ledger.")

    # Digest binding (spec 5.4): confirm the digest the receipt vouches for is
    # the artefact actually being deployed.
    parsed = Sign1Message.decode(signed_statement)
    cwt = parsed.phdr.get(crypto.CWTClaims, {})
    sub = cwt.get(crypto.CWT_SUB)
    iss = cwt.get(crypto.CWT_ISS)
    print(f"  issuer:          {iss}")
    print(f"  registered digest: {sub}")

    expected = None
    if args.digest:
        expected = args.digest if ":" in args.digest else "sha256:" + args.digest
    elif args.artifact:
        expected = _digest_file(Path(args.artifact))

    if expected is not None:
        if expected == sub:
            print(f"  digest binding:  OK ({expected} matches the loaded artefact)")
        else:
            raise SystemExit(
                f"DIGEST MISMATCH: receipt vouches for {sub} but the artefact "
                f"you supplied hashes to {expected}."
            )
    else:
        print(
            "  digest binding:  SKIPPED (pass --artifact or --digest to bind the "
            "receipt to a specific artefact)."
        )
    for d in details:
        if d.get("regtxid"):
            print(f"  registered at tx: {d['regtxid']}")
