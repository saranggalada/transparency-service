# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""`ts` -- the Transparency Service CLI.

A thin wrapper over the SCITT CCF ledger's client library and governance surface,
serving submitters (Inference Providers, Platform Operators) and the TS operator.
"""

import argparse

from . import artefact, governance, policy
from .constants import ARTEFACT_TYPES

TYPES = list(ARTEFACT_TYPES.keys())


def build_parser():
    parser = argparse.ArgumentParser(
        prog="ts", description="Transparency Service CLI (SCITT CCF)."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ---- submitter / user verbs ----
    p = sub.add_parser("sign-artifact", help="Build and sign a Signed Statement.")
    p.add_argument("--type", choices=TYPES, required=True, help="Artefact type.")
    p.add_argument("--artifact", help="Path to the artefact to hash (image tar, weights, yaml).")
    p.add_argument("--digest", help="Pre-computed sha256 digest (hex or sha256:hex).")
    p.add_argument("--name", help="Human-readable artefact name.")
    p.add_argument("--sbom", help="Path to an SBOM file; its digest is recorded as a required claim.")
    p.add_argument("--svn", type=int, default=0, help="Software version number.")
    p.add_argument("--claim", action="append", help="Extra key=value claim (repeatable).")
    p.add_argument("--out", required=True, help="Output signed statement (.cose).")
    p.set_defaults(func=artefact.sign_artifact)

    p = sub.add_parser("submit-artifact", help="Register a signed statement; get a receipt.")
    p.add_argument("statement", help="Signed statement (.cose) to submit.")
    p.add_argument("--out", required=True, help="Output transparent statement (.cose).")
    p.set_defaults(func=artefact.submit_artifact)

    p = sub.add_parser("fetch-receipt", help="Fetch the transparent statement for a txid.")
    p.add_argument("txid", help="Ledger transaction id (e.g. 2.14).")
    p.add_argument("--out", required=True, help="Output transparent statement (.cose).")
    p.set_defaults(func=artefact.fetch_receipt)

    p = sub.add_parser("query", help="Query and print a recorded ledger entry by txid.")
    p.add_argument("txid", help="Ledger transaction id (e.g. 2.14).")
    p.add_argument("--out", help="Optionally also write the transparent statement (.cose).")
    p.set_defaults(func=artefact.query)

    p = sub.add_parser("validate-artifact", help="Locally verify a transparent statement.")
    p.add_argument("statement", help="Transparent statement (.cose) to verify.")
    p.add_argument("--artifact", help="Artefact to bind the receipt to (recomputes digest).")
    p.add_argument("--digest", help="Digest to bind the receipt to (hex or sha256:hex).")
    p.add_argument("--trust-store", help="Folder with the TS service keys (scitt-keys.cbor).")
    p.set_defaults(func=artefact.validate_artifact)

    # ---- managing-entity verbs ----
    pol = sub.add_parser("policy", help="View / update registration policies.")
    pol_sub = pol.add_subparsers(dest="policy_command", required=True)

    ps = pol_sub.add_parser("show", help="Show a policy fragment or the active merged policy.")
    ps.add_argument("type", choices=TYPES + ["active"])
    ps.set_defaults(func=policy.policy_show)

    pb = pol_sub.add_parser("build", help="Recompose the merged policy locally.")
    pb.set_defaults(func=policy.policy_build)

    pp = pol_sub.add_parser("propose", help="Update a policy fragment and propose it.")
    pp.add_argument("type", choices=TYPES)
    pp.add_argument("file", nargs="?", help="New Rego fragment (omit to re-propose current).")
    pp.add_argument("--allow-open", action="store_true", help="Do not fail if proposal stays open.")
    pp.set_defaults(func=policy.policy_propose)

    gov = sub.add_parser("governance", help="Governance member management (thin stubs).")
    gov_sub = gov.add_subparsers(dest="gov_command", required=True)

    ga = gov_sub.add_parser("activate-member", help="Activate the configured member.")
    ga.set_defaults(func=governance.member_activate)

    gm = gov_sub.add_parser("add-member", help="Propose adding a governance member.")
    gm.add_argument("cert", help="PEM certificate of the new member.")
    gm.add_argument("--allow-open", action="store_true")
    gm.set_defaults(func=governance.member_add)

    gc = gov_sub.add_parser("constitution", help="Print the active constitution.")
    gc.set_defaults(func=governance.constitution_show)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
