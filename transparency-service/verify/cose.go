// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Package verify implements the runtime Transparent Statement verification the
// KMS, Certificate Manager and Controller each perform before trusting an
// artefact (see the Transparency Service spec, section 5).
package verify

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/fxamacker/cbor/v2"
)

// logger is an optional trace sink. When non-nil, the verifier emits the actual
// cryptographic artefacts (hashes, signatures, Merkle root) at each step so an
// operator can see, rather than take on faith, why a check passed or failed.
type logger func(string, ...any)

func (l logger) printf(format string, a ...any) {
	if l != nil {
		l(format, a...)
	}
}

func hexOf(b []byte) string { return hex.EncodeToString(b) }

// hexTrunc renders a big.Int as a short, human-scannable hex prefix.
func hexTrunc(x *big.Int) string {
	s := hex.EncodeToString(x.Bytes())
	if len(s) > 20 {
		return s[:20] + "…"
	}
	return s
}

// COSE header labels and algorithm identifiers we rely on.
const (
	labelAlg      = 1
	labelCty      = 3
	labelKid      = 4
	labelCWT      = 15  // CWT_Claims
	labelX5chain  = 33  // x5chain
	labelReceipts = 394 // SCITT receipts (unprotected)

	algES256 = -7
	algES384 = -35
	algES512 = -36
)

// CWT claim keys (RFC 9597 / SCITT usage).
const (
	cwtISS = 1
	cwtSUB = 2
	cwtIAT = 6
	cwtSVN = "svn"
)

// sign1 is a decoded COSE_Sign1 structure with the protected header kept as raw
// bytes (it is signed verbatim, so must never be re-encoded).
type sign1 struct {
	protectedRaw []byte
	unprotected  map[any]cbor.RawMessage
	payload      []byte
	signature    []byte
}

// tag18 mirrors the COSE_Sign1 array [protected, unprotected, payload, signature].
type coseArray struct {
	_            struct{} `cbor:",toarray"`
	Protected    cbor.RawMessage
	Unprotected  cbor.RawMessage
	Payload      cbor.RawMessage
	Signature    []byte
}

func decodeSign1(data []byte) (*sign1, error) {
	// COSE_Sign1 may be wrapped in tag 18; unwrap if present.
	var rt cbor.RawTag
	if err := cbor.Unmarshal(data, &rt); err == nil && rt.Number == 18 {
		data = rt.Content
	}
	var arr coseArray
	if err := cbor.Unmarshal(data, &arr); err != nil {
		return nil, fmt.Errorf("not a COSE_Sign1 array: %w", err)
	}
	// Protected is a bstr wrapping a header map; keep the inner bytes.
	var protectedBytes []byte
	if err := cbor.Unmarshal(arr.Protected, &protectedBytes); err != nil {
		return nil, fmt.Errorf("protected header not a bstr: %w", err)
	}
	uhdr := map[any]cbor.RawMessage{}
	if len(arr.Unprotected) > 0 {
		_ = cbor.Unmarshal(arr.Unprotected, &uhdr)
	}
	var payload []byte
	if len(arr.Payload) > 0 {
		_ = cbor.Unmarshal(arr.Payload, &payload) // nil for detached payloads
	}
	return &sign1{
		protectedRaw: protectedBytes,
		unprotected:  uhdr,
		payload:      payload,
		signature:    arr.Signature,
	}, nil
}

// protectedMap parses the protected header bytes into a label->value map.
func (s *sign1) protectedMap() (map[any]cbor.RawMessage, error) {
	m := map[any]cbor.RawMessage{}
	if len(s.protectedRaw) == 0 {
		return m, nil
	}
	if err := cbor.Unmarshal(s.protectedRaw, &m); err != nil {
		return nil, fmt.Errorf("decode protected header: %w", err)
	}
	return m, nil
}

var canonical, _ = cbor.CanonicalEncOptions().EncMode()

// sigStructure builds the COSE Sig_structure ("Signature1") to-be-signed bytes.
// externalPayload, when non-nil, supplies a detached payload (used by receipts).
func (s *sign1) sigStructure(externalPayload []byte) ([]byte, error) {
	payload := s.payload
	if externalPayload != nil {
		payload = externalPayload
	}
	protected := s.protectedRaw
	// Sig_structure requires the protected header re-wrapped as a bstr.
	protectedBstr, err := canonical.Marshal(protected)
	if err != nil {
		return nil, err
	}
	var pb cbor.RawMessage = protectedBstr
	st := []any{"Signature1", pb, []byte{}, payload}
	return canonical.Marshal(st)
}

// verifyECDSA verifies the COSE_Sign1 signature over the given (possibly
// detached) payload using an ECDSA public key and COSE algorithm id. When log
// is non-nil it prints the actual bytes it hashed, the signature, and the
// MATCH/MISMATCH outcome.
func (s *sign1) verifyECDSA(pub *ecdsa.PublicKey, alg int, externalPayload []byte, log logger) error {
	tbs, err := s.sigStructure(externalPayload)
	if err != nil {
		return err
	}
	var digest []byte
	switch alg {
	case algES256:
		h := sha256.Sum256(tbs)
		digest = h[:]
	case algES384:
		h := sha512.Sum384(tbs)
		digest = h[:]
	case algES512:
		h := sha512.Sum512(tbs)
		digest = h[:]
	default:
		return fmt.Errorf("unsupported COSE algorithm %d", alg)
	}
	n := (pub.Curve.Params().BitSize + 7) / 8
	if len(s.signature) != 2*n {
		return fmt.Errorf("unexpected signature length %d (want %d)", len(s.signature), 2*n)
	}
	r := new(big.Int).SetBytes(s.signature[:n])
	sVal := new(big.Int).SetBytes(s.signature[n:])
	ok := ecdsa.Verify(pub, digest, r, sVal)
	log.printf("      COSE alg:            %d", alg)
	log.printf("      Sig_structure (TBS): %d bytes, SHA-256 = %s", len(tbs), hex.EncodeToString(digest))
	log.printf("      signature r:         %s", hex.EncodeToString(s.signature[:n]))
	log.printf("      signature s:         %s", hex.EncodeToString(s.signature[n:]))
	log.printf("      signer public key:   x=%s y=%s", hexTrunc(pub.X), hexTrunc(pub.Y))
	if !ok {
		log.printf("      ECDSA verify:        MISMATCH [FAIL]")
		return fmt.Errorf("COSE signature verification failed")
	}
	log.printf("      ECDSA verify:        MATCH [OK]")
	return nil
}
