// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package verify

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
)

// DidX509 is a parsed did:x509 issuer of the form
//
//	did:x509:0:sha256:<b64url-CA-fingerprint>::eku:<oid>
type DidX509 struct {
	CAFingerprint string // base64url (no padding) SHA-256 of the anchor CA cert
	EKU           string // required leaf Extended Key Usage OID
	Raw           string
}

// ParseDidX509 parses the subset of did:x509 the Transparency Service uses.
func ParseDidX509(did string) (*DidX509, error) {
	if !strings.HasPrefix(did, "did:x509:0:sha256:") {
		return nil, fmt.Errorf("unsupported did:x509 issuer %q", did)
	}
	rest := strings.TrimPrefix(did, "did:x509:0:sha256:")
	parts := strings.SplitN(rest, "::", 2)
	out := &DidX509{CAFingerprint: parts[0], Raw: did}
	if len(parts) == 2 {
		for _, policy := range strings.Split(parts[1], "::") {
			if kv := strings.SplitN(policy, ":", 2); len(kv) == 2 && kv[0] == "eku" {
				out.EKU = kv[1]
			}
		}
	}
	if out.EKU == "" {
		return nil, fmt.Errorf("did:x509 issuer %q has no ::eku policy", did)
	}
	return out, nil
}

func caFingerprintB64URL(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// verifyDidX509 checks that the leaf certificate's chain resolves to the CA
// named in the issuer DID, that the named CA is one of the pinned trust anchors,
// and that the leaf carries the DID's required EKU. It returns the leaf cert.
//
// This is the independent, self-contained trust-anchor check the spec calls for
// (section 5.3): no network lookup is needed because the anchor fingerprint is
// baked into the issuer and the full chain travels in the x5chain.
func verifyDidX509(issuer string, chain []*x509.Certificate, allowedAnchors map[string]bool, log logger) (*x509.Certificate, error) {
	did, err := ParseDidX509(issuer)
	if err != nil {
		return nil, err
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("empty x5chain")
	}
	leaf := chain[0]
	log.printf("      issuer DID:        %s", did.Raw)
	log.printf("      DID anchor (fp):   sha256/%s", did.CAFingerprint)
	log.printf("      required EKU:      %s", did.EKU)
	log.printf("      leaf subject:      %s (fp sha256/%s)", leaf.Subject.CommonName, caFingerprintB64URL(leaf))

	// Locate the anchor cert named by the DID fingerprint within the chain.
	var anchor *x509.Certificate
	for _, c := range chain {
		if caFingerprintB64URL(c) == did.CAFingerprint {
			anchor = c
			break
		}
	}
	if anchor == nil {
		return nil, fmt.Errorf("no certificate in x5chain matches did:x509 anchor fingerprint %s", did.CAFingerprint)
	}
	log.printf("      anchor in x5chain: %s (fp matches DID) [OK]", anchor.Subject.CommonName)
	if allowedAnchors != nil && !allowedAnchors[did.CAFingerprint] {
		log.printf("      pinned anchor:     NOT in operator allow-list [FAIL]")
		return nil, fmt.Errorf("did:x509 anchor %s is not a pinned trust anchor", did.CAFingerprint)
	}
	if allowedAnchors != nil {
		log.printf("      pinned anchor:     in operator allow-list [OK]")
	}

	// Verify the certificate chain up to the anchor.
	roots := x509.NewCertPool()
	roots.AddCert(anchor)
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		if c != anchor {
			inter.AddCert(c)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		log.printf("      chain verify:      %v [FAIL]", err)
		return nil, fmt.Errorf("x5chain does not verify to anchor: %w", err)
	}
	log.printf("      chain verify:      leaf -> anchor signature valid [OK]")

	// Enforce the leaf EKU named by the DID.
	if !leafHasEKU(leaf, did.EKU) {
		log.printf("      EKU check:         leaf missing %s [FAIL]", did.EKU)
		return nil, fmt.Errorf("leaf certificate is missing required EKU %s", did.EKU)
	}
	log.printf("      EKU check:         leaf carries %s [OK]", did.EKU)
	return leaf, nil
}

func leafHasEKU(leaf *x509.Certificate, oid string) bool {
	for _, u := range leaf.UnknownExtKeyUsage {
		if u.String() == oid {
			return true
		}
	}
	// Also map a few well-known OIDs Go recognises, in case a real CA uses them.
	known := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageCodeSigning: "1.3.6.1.5.5.7.3.3",
	}
	for _, u := range leaf.ExtKeyUsage {
		if known[u] == oid {
			return true
		}
	}
	return false
}
