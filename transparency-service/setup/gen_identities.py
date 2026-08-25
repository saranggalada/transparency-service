# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Generate the code-signing trust anchors (CAs) and per-artefact-type signing
identities used by the Transparency Service demo.

For each of the two CAs (``platform`` and ``provider``) we create a self-signed
root. For each artefact type we then issue a leaf certificate under the relevant
CA carrying that type's EKU, and derive the ``did:x509`` issuer string the
submitter will use. The ``did:x509`` trust anchor is the *root CA fingerprint*,
which is embedded directly in the issuer string and resolved from the x5chain in
each signed statement -- so no separate on-ledger anchor registration is needed;
the Rego policy simply pins the acceptable issuer strings.

In production these CAs are replaced by a real external code-signing CA
(commercial, Sigstore Fulcio, or a confidential CA); only the certificates and
keys change, not the flow.

Outputs (under --output-dir, default transparency-service/identities/):
    <ca>_ca_cert.pem, <ca>_ca_key.pem                 the CA roots
    <type>_key.pem, <type>_x5c.pem                     per-type signing key + chain
    issuers.json                                       resolved did:x509 issuers
"""

import argparse
import datetime
import json
import sys
from pathlib import Path

# Make pyscitt importable when run from the repo root.
REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "pyscitt"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from pyscitt import crypto  # noqa: E402

from tscli.constants import ARTEFACT_TYPES, CAS  # noqa: E402

# Demo certificate validity. pyscitt's own helper mints 10-day certs, which is
# too short for a service whose receipts are meant to outlive deployments, so we
# generate longer-lived certs here.
VALIDITY_DAYS = 365


def _load_priv(pem: str):
    return serialization.load_pem_private_key(pem.encode(), None)


def _cert_pem(cert) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def make_ca(cn: str):
    key_pem, _ = crypto.generate_ec_keypair("P-256")
    key = _load_priv(key_pem)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.UTC)
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        # CCF's did:x509 resolver requires Subject/Authority Key Identifiers.
        .add_extension(ski, critical=False)
        .sign(key, hashes.SHA256())
    )
    return key_pem, _cert_pem(cert)


def make_leaf(ca_key_pem, ca_cert_pem, eku, cn):
    key_pem, _ = crypto.generate_ec_keypair("P-256")
    key = _load_priv(key_pem)
    ca_key = _load_priv(ca_key_pem)
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode())
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.ObjectIdentifier(eku)]), critical=False
        )
        # CCF's did:x509 resolver requires Subject/Authority Key Identifiers.
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return key_pem, _cert_pem(cert)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=REPO_ROOT / "transparency-service" / "identities",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite identities even if they already exist.",
    )
    args = parser.parse_args()

    out = args.output_dir
    out.mkdir(parents=True, exist_ok=True)

    issuers_path = out / "issuers.json"
    if issuers_path.exists() and not args.force:
        print(f"Identities already exist at {out} (use --force to regenerate).")
        return

    cas = {}
    result = {"cas": {}, "issuers": {}, "artefact_types": {}}
    for ca_name in CAS:
        key, cert = make_ca(f"TS {ca_name} CA")
        (out / f"{ca_name}_ca_key.pem").write_text(key)
        (out / f"{ca_name}_ca_cert.pem").write_text(cert)
        fingerprint = crypto.get_cert_fingerprint_b64url(cert)
        cas[ca_name] = (key, cert, fingerprint)
        result["cas"][ca_name] = {"fingerprint_b64url": fingerprint}
        print(f"CA '{ca_name}': did:x509 root fingerprint sha256:{fingerprint}")

    for type_name, spec in ARTEFACT_TYPES.items():
        ca_key, ca_cert, fingerprint = cas[spec["ca"]]
        leaf_key, leaf_cert = make_leaf(
            ca_key, ca_cert, spec["eku"], f"TS {type_name} signer"
        )
        (out / f"{type_name}_key.pem").write_text(leaf_key)
        # x5chain: leaf first, then issuing CA root.
        (out / f"{type_name}_x5c.pem").write_text(leaf_cert + ca_cert)

        issuer = f"did:x509:0:sha256:{fingerprint}::eku:{spec['eku']}"
        result["issuers"][type_name] = issuer
        result["artefact_types"][type_name] = {
            "ca": spec["ca"],
            "eku": spec["eku"],
            "content_type": spec["content_type"],
        }
        print(f"Type '{type_name}': issuer {issuer}")

    issuers_path.write_text(json.dumps(result, indent=2) + "\n")
    print(f"\nWrote identities to {out}")


if __name__ == "__main__":
    main()
