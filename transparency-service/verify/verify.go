// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package verify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

// Claims are the artefact facts a verified Transparent Statement attests to.
type Claims struct {
	Issuer      string         `json:"issuer"`
	Digest      string         `json:"digest"` // CWT sub
	SVN         int            `json:"svn"`
	ContentType string         `json:"content_type"`
	Payload     map[string]any `json:"payload,omitempty"`
}

// Options pins the trust the verifier will accept.
type Options struct {
	// TSKeys are the Transparency Service's own signing keys, keyed by hex kid,
	// fetched once from /.well-known/transparency-configuration and pinned.
	TSKeys map[string]*ecdsa.PublicKey
	// AllowedAnchors is the set of base64url did:x509 CA fingerprints that are
	// trusted code-signing anchors. If nil, any anchor named in the DID whose
	// chain verifies is accepted (not recommended for production).
	AllowedAnchors map[string]bool
	// Log, when non-nil, receives a step-by-step trace of the actual
	// cryptographic evidence (hashes, signatures, Merkle root) checked.
	Log logger
}

// VerifyArtefact is the single runtime entry point the KMS, Certificate Manager
// and Controller each call before trusting an artefact (spec section 5).
//
// It verifies, in order:
//  1. the Receipt's COSE signature against a pinned Transparency Service key;
//  2. the Receipt's Merkle inclusion proof against the root it signs;
//  3. the Signed Statement's own COSE signature and did:x509 issuer chaining to
//     a pinned trust anchor;
//  4. that digest matches the digest the statement actually registered.
//
// digest is the artefact being loaded ("sha256:<hex>" or "<hex>").
func VerifyArtefact(digest string, signedStatement, receipt []byte, opts Options) (bool, *Claims, error) {
	ss, err := decodeSign1(signedStatement)
	if err != nil {
		return false, nil, fmt.Errorf("signed statement: %w", err)
	}
	phdr, err := ss.protectedMap()
	if err != nil {
		return false, nil, err
	}

	alg, err := intAt(phdr, labelAlg)
	if err != nil {
		return false, nil, fmt.Errorf("signed statement alg: %w", err)
	}
	chain, err := parseX5Chain(phdr)
	if err != nil {
		return false, nil, err
	}
	iss, sub, svn, err := cwtClaims(phdr)
	if err != nil {
		return false, nil, err
	}
	cty := ctyOf(phdr)

	// (3) Signed statement signature + did:x509 anchor.
	opts.Log.printf("[1/4] Issuer trust (did:x509 chain to a pinned anchor)")
	leaf, err := verifyDidX509(iss, chain, opts.AllowedAnchors, opts.Log)
	if err != nil {
		return false, nil, fmt.Errorf("issuer trust: %w", err)
	}
	leafPub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return false, nil, fmt.Errorf("unsupported leaf key type")
	}
	opts.Log.printf("[2/4] Signed Statement signature (issuer's key over the statement)")
	if err := ss.verifyECDSA(leafPub, alg, nil, opts.Log); err != nil {
		return false, nil, fmt.Errorf("signed statement signature: %w", err)
	}

	// (1)+(2) Receipt signature + inclusion proof binding to this statement.
	claimDigest := sha256.Sum256(signedStatement)
	opts.Log.printf("[3/4] Receipt: Merkle inclusion proof + Transparency Service signature")
	opts.Log.printf("      SHA-256(signed statement) = %s", hexOf(claimDigest[:]))
	if err := verifyReceipt(receipt, opts.TSKeys, claimDigest[:], opts.Log); err != nil {
		return false, nil, err
	}

	// (4) Digest binding.
	opts.Log.printf("[4/4] Digest binding (artefact bytes vs registered subject)")
	opts.Log.printf("      artefact digest  = %s", normDigest(digest))
	opts.Log.printf("      registered (sub) = %s", sub)
	if normDigest(digest) != normDigest(sub) {
		opts.Log.printf("      binding:           MISMATCH [FAIL]")
		return false, nil, fmt.Errorf("digest mismatch: artefact is %s but statement registered %s", normDigest(digest), sub)
	}
	opts.Log.printf("      binding:           MATCH [OK]")

	claims := &Claims{Issuer: iss, Digest: sub, SVN: svn, ContentType: cty}
	if len(ss.payload) > 0 {
		_ = json.Unmarshal(ss.payload, &claims.Payload)
	}
	return true, claims, nil
}

// VerifyTransparentStatement is a convenience wrapper when you only have a
// transparent statement (signed statement with the receipt(s) embedded in the
// unprotected header, label 394), as produced by `ts submit-artifact`.
func VerifyTransparentStatement(digest string, transparent []byte, opts Options) (bool, *Claims, error) {
	ts, err := decodeSign1(transparent)
	if err != nil {
		return false, nil, err
	}
	receiptsRaw, ok := ts.unprotected[uint64(labelReceipts)]
	if !ok {
		if receiptsRaw, ok = ts.unprotected[int64(labelReceipts)]; !ok {
			return false, nil, fmt.Errorf("no receipts (394) in transparent statement")
		}
	}
	var receipts [][]byte
	if err := cbor.Unmarshal(receiptsRaw, &receipts); err != nil || len(receipts) == 0 {
		return false, nil, fmt.Errorf("could not decode receipts: %w", err)
	}
	// Reconstruct the exact submitted signed statement: same COSE_Sign1 with an
	// empty unprotected header.
	signed, err := stripUnprotected(transparent)
	if err != nil {
		return false, nil, err
	}
	return VerifyArtefact(digest, signed, receipts[0], opts)
}

// stripUnprotected re-encodes a COSE_Sign1 with an empty unprotected header,
// reproducing the bytes the ledger hashed at registration.
func stripUnprotected(data []byte) ([]byte, error) {
	tag := true
	var rt cbor.RawTag
	if err := cbor.Unmarshal(data, &rt); err == nil && rt.Number == 18 {
		data = rt.Content
	} else {
		tag = false
	}
	var arr coseArray
	if err := cbor.Unmarshal(data, &arr); err != nil {
		return nil, err
	}
	emptyMap, _ := canonical.Marshal(map[int]any{})
	out := coseArray{
		Protected:   arr.Protected,
		Unprotected: emptyMap,
		Payload:     arr.Payload,
		Signature:   arr.Signature,
	}
	body, err := canonical.Marshal(out)
	if err != nil {
		return nil, err
	}
	if tag {
		return canonical.Marshal(cbor.RawTag{Number: 18, Content: body})
	}
	return body, nil
}

// ---- helpers to read protected-header fields ----

func rawAt(m map[any]cbor.RawMessage, label int) (cbor.RawMessage, bool) {
	if v, ok := m[int64(label)]; ok {
		return v, true
	}
	if v, ok := m[uint64(label)]; ok {
		return v, true
	}
	return nil, false
}

func intAt(m map[any]cbor.RawMessage, label int) (int, error) {
	raw, ok := rawAt(m, label)
	if !ok {
		return 0, fmt.Errorf("missing header %d", label)
	}
	var v int
	return v, cbor.Unmarshal(raw, &v)
}

func ctyOf(m map[any]cbor.RawMessage) string {
	raw, ok := rawAt(m, labelCty)
	if !ok {
		return ""
	}
	var s string
	if cbor.Unmarshal(raw, &s) == nil {
		return s
	}
	return ""
}

func parseX5Chain(m map[any]cbor.RawMessage) ([]*x509.Certificate, error) {
	raw, ok := rawAt(m, labelX5chain)
	if !ok {
		return nil, fmt.Errorf("signed statement has no x5chain")
	}
	// x5chain is either a single bstr or an array of bstr.
	var ders [][]byte
	if err := cbor.Unmarshal(raw, &ders); err != nil {
		var single []byte
		if err2 := cbor.Unmarshal(raw, &single); err2 != nil {
			return nil, fmt.Errorf("decode x5chain: %w", err)
		}
		ders = [][]byte{single}
	}
	var certs []*x509.Certificate
	for _, der := range ders {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parse x5chain cert: %w", err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("empty x5chain")
	}
	return certs, nil
}

func cwtClaims(m map[any]cbor.RawMessage) (iss, sub string, svn int, err error) {
	raw, ok := rawAt(m, labelCWT)
	if !ok {
		return "", "", 0, fmt.Errorf("signed statement has no CWT claims")
	}
	cwt := map[any]cbor.RawMessage{}
	if err := cbor.Unmarshal(raw, &cwt); err != nil {
		return "", "", 0, fmt.Errorf("decode CWT claims: %w", err)
	}
	if v, ok := rawAt(cwt, cwtISS); ok {
		_ = cbor.Unmarshal(v, &iss)
	}
	if v, ok := rawAt(cwt, cwtSUB); ok {
		_ = cbor.Unmarshal(v, &sub)
	}
	if v, ok := cwt[cwtSVN]; ok {
		_ = cbor.Unmarshal(v, &svn)
	}
	return iss, sub, svn, nil
}

func normDigest(d string) string {
	d = strings.TrimSpace(d)
	if !strings.Contains(d, ":") {
		return "sha256:" + d
	}
	return d
}

// LoadTSKeys parses a COSE_Key_Set (the CBOR body of /.well-known/scitt-keys)
// into pinned ECDSA public keys, keyed by hex kid.
func LoadTSKeys(coseKeySet []byte) (map[string]*ecdsa.PublicKey, error) {
	var keys []map[int]cbor.RawMessage
	if err := cbor.Unmarshal(coseKeySet, &keys); err != nil {
		return nil, fmt.Errorf("decode COSE_Key_Set: %w", err)
	}
	out := map[string]*ecdsa.PublicKey{}
	for _, k := range keys {
		var kty int
		if err := cbor.Unmarshal(k[1], &kty); err != nil || kty != 2 { // EC2
			continue
		}
		var crv int
		var x, y, kid []byte
		_ = cbor.Unmarshal(k[-1], &crv)
		_ = cbor.Unmarshal(k[-2], &x)
		_ = cbor.Unmarshal(k[-3], &y)
		_ = cbor.Unmarshal(k[2], &kid)
		var curve elliptic.Curve
		switch crv {
		case 1:
			curve = elliptic.P256()
		case 2:
			curve = elliptic.P384()
		case 3:
			curve = elliptic.P521()
		default:
			continue
		}
		out[string(kid)] = &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(x),
			Y:     new(big.Int).SetBytes(y),
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no usable EC keys in COSE_Key_Set")
	}
	return out, nil
}
