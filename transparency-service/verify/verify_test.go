// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package verify

import "testing"

func TestParseDidX509(t *testing.T) {
	did := "did:x509:0:sha256:Et2tLPx7bb0PtA-xMiXmlq2ekJQH0rDRRhL3QV1dmOA::eku:1.3.6.1.4.1.58270.1.1"
	d, err := ParseDidX509(did)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if d.CAFingerprint != "Et2tLPx7bb0PtA-xMiXmlq2ekJQH0rDRRhL3QV1dmOA" {
		t.Errorf("fingerprint = %q", d.CAFingerprint)
	}
	if d.EKU != "1.3.6.1.4.1.58270.1.1" {
		t.Errorf("eku = %q", d.EKU)
	}
}

func TestParseDidX509Rejects(t *testing.T) {
	for _, bad := range []string{
		"did:web:example.com",
		"did:x509:0:sha256:abc", // no eku policy
	} {
		if _, err := ParseDidX509(bad); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

func TestNormDigest(t *testing.T) {
	if normDigest("abc") != "sha256:abc" {
		t.Error("bare hex should get sha256: prefix")
	}
	if normDigest("sha256:abc") != "sha256:abc" {
		t.Error("prefixed digest should be unchanged")
	}
}
