# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Managing-entity verbs: inspect and update the registration policies.

The ledger runs a single merged Rego policy; these verbs let the operator view a
per-artefact-type fragment and propose an update, which recomposes and re-submits
the merged policy via a ``set_scitt_configuration`` governance proposal.
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path

from pyscitt import governance
from pyscitt.client import Client
from pyscitt.local_key_sign_client import LocalKeySignClient

from .config import TS_ROOT, Config
from .constants import artefact_type_names

POLICY_DIR = TS_ROOT / "policies"
BUILD_POLICY = TS_ROOT / "setup" / "build_policy.py"


def _resolved_fragment(type_name: str, cfg: Config) -> str:
    fragment = (POLICY_DIR / f"{type_name}.rego").read_text()
    try:
        issuer = cfg.issuers()["issuers"][type_name]
        fragment = fragment.replace(f"__{type_name.upper()}_ISSUER__", issuer)
    except SystemExit:
        pass
    return fragment


def policy_show(args):
    cfg = Config()
    if args.type == "active":
        # Print the merged policy that would be (or is) applied.
        merged = cfg.identities_dir / "policy.rego"
        if merged.exists():
            print(merged.read_text())
        else:
            print("No merged policy built yet. Run: ts policy build")
        return
    print(_resolved_fragment(args.type, cfg))


def policy_build(args):
    subprocess.run([sys.executable, str(BUILD_POLICY)], check=True)


def policy_propose(args):
    cfg = Config()
    dest = POLICY_DIR / f"{args.type}.rego"
    if args.file:
        shutil.copyfile(args.file, dest)
        print(f"Updated fragment {dest}")

    # Recompose the merged policy + configuration proposal.
    subprocess.run([sys.executable, str(BUILD_POLICY)], check=True)
    config = json.loads((cfg.identities_dir / "configuration.json").read_text())

    proposal = governance.set_scitt_configuration_proposal(config)
    client = Client(
        cfg.url,
        development=cfg.development,
        member_auth=LocalKeySignClient(
            cfg.member_cert.read_text(), cfg.member_key.read_text()
        ),
    )
    result = client.governance.propose(proposal, must_pass=not args.allow_open)
    if result.is_accepted:
        print("Policy proposal accepted and active.")
    elif result.is_open:
        print(f"Proposal {result.id} is still open; more member votes needed.")
    else:
        print(f"Proposal {result.id} is {result.state}")
