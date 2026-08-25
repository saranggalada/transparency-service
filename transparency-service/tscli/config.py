# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Resolves paths and endpoints for the ``ts`` CLI.

Everything can be overridden by environment variables; the defaults target a
local virtual-mode ledger started with ``docker/run-dev.sh`` from the repo root.
"""

import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TS_ROOT = REPO_ROOT / "transparency-service"


class Config:
    def __init__(self):
        self.url = os.environ.get("SCITT_URL", "https://127.0.0.1:8000")
        self.identities_dir = Path(
            os.environ.get("TS_IDENTITIES_DIR", TS_ROOT / "identities")
        )
        self.trust_store_dir = Path(
            os.environ.get(
                "TS_TRUST_STORE", self.identities_dir / "service_trust_store"
            )
        )
        self.member_cert = Path(
            os.environ.get("TS_MEMBER_CERT", REPO_ROOT / "workspace" / "member0_cert.pem")
        )
        self.member_key = Path(
            os.environ.get("TS_MEMBER_KEY", REPO_ROOT / "workspace" / "member0_privk.pem")
        )
        # Virtual-mode ledger uses a self-signed service cert; skip TLS verify.
        self.development = os.environ.get("TS_DEVELOPMENT", "1") == "1"

    def issuers(self) -> dict:
        import json

        path = self.identities_dir / "issuers.json"
        if not path.exists():
            raise SystemExit(
                f"No identities found at {path}.\n"
                "Run: transparency-service/setup/gen-identities"
            )
        return json.loads(path.read_text())
