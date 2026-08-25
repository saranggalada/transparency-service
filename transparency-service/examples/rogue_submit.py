# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Attempt to register an artefact signed by an *untrusted* CA.

Demonstrates that the registration policy rejects statements whose did:x509
issuer is not a pinned trust anchor -- i.e. the ledger enforces policy at
registration time, not just at verification time.
"""

import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "pyscitt"))

from pyscitt import crypto
from pyscitt.client import Client, ServiceError

url = os.environ.get("SCITT_URL", "https://127.0.0.1:8000")

# A rogue CA + leaf that no policy trusts.
ca_key, _ = crypto.generate_ec_keypair("P-256")
ca_cert = crypto.generate_cert(ca_key, ca=True, cn="Rogue CA")
leaf_key, _ = crypto.generate_ec_keypair("P-256")
leaf_cert = crypto.generate_cert(
    leaf_key, issuer=(ca_cert, ca_key), ca=False, add_eku="1.3.6.1.4.1.58270.1.1"
)
fp = crypto.get_cert_fingerprint_b64url(ca_cert)
issuer = f"did:x509:0:sha256:{fp}::eku:1.3.6.1.4.1.58270.1.1"

signer = crypto.Signer(leaf_key, issuer=issuer, x5c=[leaf_cert, ca_cert])
# Payload carries a valid container digest AND SBOM claim, so the ONLY unmet
# policy term is the untrusted identity.
payload = (
    '{"artifact_type":"component","digest":"sha256:%s",'
    '"sbom_digest":"sha256:%s","sbom_name":"rogue.spdx.json"}'
    % ("ab" * 32, "cd" * 32)
)
signed = crypto.sign_statement(
    signer,
    payload.encode(),
    content_type="application/vnd.ts.component+json",
    feed="sha256:" + ("ab" * 32),
    svn=0,
    cwt=True,
)

client = Client(url, development=True)
try:
    client.submit_signed_statement_and_wait(signed)
    print("UNEXPECTED: rogue artefact was accepted!")
    sys.exit(1)
except ServiceError as e:
    print(f"Rejected by policy as expected: {e}")
    sys.exit(0)
