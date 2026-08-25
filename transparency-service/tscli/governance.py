# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Managing-entity governance verbs (thin stubs).

The concrete membership / quorum model for the Transparency Service is not yet
finalized (spec 6, 10). Rather than build bespoke logic around an undecided
model, these verbs delegate straight to CCF's existing governance primitives
exposed by pyscitt. Extend here once the membership model is decided.
"""

from pyscitt import governance as gov
from pyscitt.client import Client
from pyscitt.local_key_sign_client import LocalKeySignClient

from .config import Config


def _member_client(cfg: Config) -> Client:
    return Client(
        cfg.url,
        development=cfg.development,
        member_auth=LocalKeySignClient(
            cfg.member_cert.read_text(), cfg.member_key.read_text()
        ),
    )


def member_activate(args):
    cfg = Config()
    _member_client(cfg).governance.activate_member()
    print("Member activated.")


def member_add(args):
    """Propose adding a new governance member from a PEM cert file.

    Stub: uses CCF's native ``set_member`` action. Quorum behaviour depends on
    the active constitution.
    """
    cfg = Config()
    cert = open(args.cert).read()
    proposal = {"actions": [{"name": "set_member", "args": {"cert": cert}}]}
    result = _member_client(cfg).governance.propose(
        proposal, must_pass=not args.allow_open
    )
    print(f"set_member proposal: {result.state} (id {result.id})")


def constitution_show(args):
    cfg = Config()
    print(_member_client(cfg).get_constitution())
