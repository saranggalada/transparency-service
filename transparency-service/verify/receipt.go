// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package verify

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// COSE receipt / CCF profile labels
// (draft-ietf-cose-merkle-tree-proofs + draft-birkholz-cose-receipts-ccf-profile).
const (
	labelVDS            = 395 // verifiable data structure (protected)
	labelVDP            = 396 // verifiable data structure proofs (unprotected)
	vdsCCFLedgerSHA256  = 2
	inclusionProofLabel = -1
	ccfProofLeafLabel   = 1
	ccfProofPathLabel   = 2
)

type pathElem struct {
	_    struct{} `cbor:",toarray"`
	Left bool
	Hash []byte
}

// verifyReceipt verifies a CCF SCITT receipt (COSE_Sign1) against the set of
// pinned Transparency Service signing keys (keyed by their hex kid), confirming
// that the given claimDigest (SHA-256 of the submitted signed statement) is
// included in the ledger's Merkle tree and that the reconstructed root is
// signed by the service.
func verifyReceipt(receiptBytes []byte, tsKeys map[string]*ecdsa.PublicKey, claimDigest []byte, log logger) error {
	r, err := decodeSign1(receiptBytes)
	if err != nil {
		return fmt.Errorf("receipt: %w", err)
	}
	phdr, err := r.protectedMap()
	if err != nil {
		return fmt.Errorf("receipt: %w", err)
	}

	// Verifiable data structure must be CCF_LEDGER_SHA256.
	vdsRaw, ok := rawAt(phdr, labelVDS)
	var vds int
	if !ok || cbor.Unmarshal(vdsRaw, &vds) != nil || vds != vdsCCFLedgerSHA256 {
		return fmt.Errorf("receipt vds header is not CCF_LEDGER_SHA256")
	}

	// Resolve the signing key by kid.
	kidRaw, ok := rawAt(phdr, labelKid)
	var kid []byte
	if !ok || cbor.Unmarshal(kidRaw, &kid) != nil {
		return fmt.Errorf("receipt missing kid")
	}
	pub, ok := tsKeys[string(kid)]
	if !ok {
		return fmt.Errorf("receipt kid %s is not a pinned Transparency Service key", string(kid))
	}
	log.printf("      receipt kid:       %s (matches a pinned TS key) [OK]", hexPrefix(kid, 16))
	algRaw, ok := rawAt(phdr, labelAlg)
	var alg int
	if !ok || cbor.Unmarshal(algRaw, &alg) != nil {
		return fmt.Errorf("receipt missing alg")
	}

	// Extract the inclusion proof(s).
	vdpRaw, ok := r.unprotected[uint64(labelVDP)]
	if !ok {
		if vdpRaw, ok = r.unprotected[int64(labelVDP)]; !ok {
			return fmt.Errorf("receipt missing verifiable data proof (396)")
		}
	}
	var vdp map[int]cbor.RawMessage
	if err := cbor.Unmarshal(vdpRaw, &vdp); err != nil {
		return fmt.Errorf("decode vdp: %w", err)
	}
	var proofs [][]byte
	if err := cbor.Unmarshal(vdp[inclusionProofLabel], &proofs); err != nil {
		return fmt.Errorf("decode inclusion proofs: %w", err)
	}
	if len(proofs) == 0 {
		return fmt.Errorf("no inclusion proofs in receipt")
	}

	for _, p := range proofs {
		var proof map[int]cbor.RawMessage
		if err := cbor.Unmarshal(p, &proof); err != nil {
			return fmt.Errorf("decode inclusion proof: %w", err)
		}
		var leaf []cbor.RawMessage
		if err := cbor.Unmarshal(proof[ccfProofLeafLabel], &leaf); err != nil || len(leaf) != 3 {
			return fmt.Errorf("malformed CCF leaf")
		}
		var internalHash, claimInLeaf []byte
		var internalData string
		_ = cbor.Unmarshal(leaf[0], &internalHash)
		_ = cbor.Unmarshal(leaf[1], &internalData)
		if err := cbor.Unmarshal(leaf[2], &claimInLeaf); err != nil {
			return fmt.Errorf("malformed CCF leaf claim digest")
		}
		log.printf("      leaf claim digest: %s", hexOf(claimInLeaf))
		if !bytes.Equal(claimInLeaf, claimDigest) {
			log.printf("      claim digest:      receipt vouches for a DIFFERENT statement [FAIL]")
			return fmt.Errorf("claim digest mismatch: receipt vouches for a different signed statement")
		}
		log.printf("      claim digest:      equals SHA-256(signed statement) [OK]")

		// accumulator = SHA256( internalHash || SHA256(internalData) || claimDigest )
		idh := sha256.Sum256([]byte(internalData))
		acc := sha256.Sum256(concat(internalHash, idh[:], claimInLeaf))
		log.printf("      Merkle leaf hash:  %s", hexOf(acc[:]))

		var path []pathElem
		if err := cbor.Unmarshal(proof[ccfProofPathLabel], &path); err != nil {
			return fmt.Errorf("decode inclusion path: %w", err)
		}
		for i, step := range path {
			side := "right"
			if step.Left {
				side = "left"
				acc = sha256.Sum256(concat(step.Hash, acc[:]))
			} else {
				acc = sha256.Sum256(concat(acc[:], step.Hash))
			}
			log.printf("        + path[%d] (%-5s sibling %s) -> %s", i, side, hexPrefix(step.Hash, 12), hexOf(acc[:]))
		}
		log.printf("      recomputed root:   %s", hexOf(acc[:]))

		// The receipt's COSE_Sign1 signs the Merkle root as a detached payload.
		log.printf("      TS signature over the recomputed root:")
		if err := r.verifyECDSA(pub, alg, acc[:], log); err != nil {
			return fmt.Errorf("receipt signature invalid: %w", err)
		}
	}
	return nil
}

func hexPrefix(b []byte, n int) string {
	s := fmt.Sprintf("%x", b)
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
