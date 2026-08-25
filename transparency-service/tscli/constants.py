# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Shared constants describing the artefact types the Transparency Service registers.

The artefact *type* is encoded by the signing certificate's Extended Key Usage
(EKU): each type has its own EKU, so the ``did:x509`` issuer string a submitter
uses already tells the ledger's Rego policy which artefact type is being
registered. This keeps a single, unified ledger policy able to enforce one rule
per artefact type without needing to parse the (hex-encoded) payload in-policy.
"""

# Private-enterprise OID arc used for demo signing EKUs. Replace with your own
# CA's real code-signing EKUs in production.
_ARC = "1.3.6.1.4.1.58270.1"

# Artefact type -> metadata.
#   ca:           which trust anchor (code-signing CA) signs this type.
#   eku:          Extended Key Usage OID that selects this type in policy.
#   content_type: COSE content-type stored in the signed statement.
ARTEFACT_TYPES = {
    "component": {
        "ca": "platform",
        "eku": f"{_ARC}.1",
        "content_type": "application/vnd.ts.component+json",
        "description": "Platform component container image "
        "(KServe controller, cert-manager, registry, backend, frontend).",
    },
    "model": {
        "ca": "provider",
        "eku": f"{_ARC}.2",
        "content_type": "application/vnd.ts.model+json",
        "description": "AI model weights belonging to an Inference Provider.",
    },
    "inferencegraph": {
        "ca": "provider",
        "eku": f"{_ARC}.3",
        "content_type": "application/vnd.ts.inferencegraph+json",
        "description": "InferenceGraph definition (KServe topology).",
    },
}

# Code-signing CAs (trust anchors) used as did:x509 roots.
CAS = {
    "platform": "Platform release CA (signs platform component images).",
    "provider": "Inference Provider CA (signs models and InferenceGraphs).",
}


def artefact_type_names():
    return list(ARTEFACT_TYPES.keys())
