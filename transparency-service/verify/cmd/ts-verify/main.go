// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Command ts-verify is a thin CLI over the shared verification library. It
// mirrors what the KMS, Certificate Manager and Controller do at runtime before
// trusting an artefact.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	verify "github.com/microsoft/scitt-ccf-ledger/transparency-service/verify"
)

func main() {
	var (
		transparent = flag.String("transparent", "", "Transparent statement (.cose) with embedded receipt")
		signed      = flag.String("signed", "", "Signed statement (.cose)")
		receipt     = flag.String("receipt", "", "Receipt (.cose), with --signed")
		artifact    = flag.String("artifact", "", "Artefact file to bind (recomputes sha256)")
		digest      = flag.String("digest", "", "Artefact digest to bind (hex or sha256:hex)")
		trustStore  = flag.String("trust-store", "", "Path to scitt-keys.cbor (pinned TS keys)")
		anchorsFile = flag.String("anchors", "", "Path to issuers.json listing pinned did:x509 anchors")
		verbose     = flag.Bool("verbose", false, "Print the actual cryptographic evidence at each step")
	)
	flag.BoolVar(verbose, "v", false, "Shorthand for --verbose")
	flag.Parse()

	d := *digest
	if d == "" && *artifact != "" {
		b, err := os.ReadFile(*artifact)
		must(err)
		sum := sha256.Sum256(b)
		d = "sha256:" + hex.EncodeToString(sum[:])
	}
	if d == "" {
		fail("provide --digest or --artifact to bind the receipt to an artefact")
	}

	must2(*trustStore != "", "--trust-store is required")
	ksBytes, err := os.ReadFile(*trustStore)
	must(err)
	tsKeys, err := verify.LoadTSKeys(ksBytes)
	must(err)

	var anchors map[string]bool
	if *anchorsFile != "" {
		anchors = loadAnchors(*anchorsFile)
	}

	opts := verify.Options{TSKeys: tsKeys, AllowedAnchors: anchors}
	if *verbose {
		opts.Log = func(format string, a ...any) { fmt.Printf(format+"\n", a...) }
		fmt.Printf("Verifying artefact digest %s\n", d)
	}

	var ok bool
	var claims *verify.Claims
	if *transparent != "" {
		b, err := os.ReadFile(*transparent)
		must(err)
		ok, claims, err = verify.VerifyTransparentStatement(d, b, opts)
		reportErr(err)
	} else {
		must2(*signed != "" && *receipt != "", "provide --transparent, or both --signed and --receipt")
		sb, err := os.ReadFile(*signed)
		must(err)
		rb, err := os.ReadFile(*receipt)
		must(err)
		ok, claims, err = verify.VerifyArtefact(d, sb, rb, opts)
		reportErr(err)
	}

	if !ok {
		fail("verification failed")
	}
	out, _ := json.MarshalIndent(claims, "", "  ")
	fmt.Println("VERIFIED: artefact has a valid Transparency Service receipt and matches a pinned trust anchor.")
	fmt.Println(string(out))
}

func loadAnchors(path string) map[string]bool {
	b, err := os.ReadFile(path)
	must(err)
	var doc struct {
		CAs map[string]struct {
			Fingerprint string `json:"fingerprint_b64url"`
		} `json:"cas"`
	}
	must(json.Unmarshal(b, &doc))
	out := map[string]bool{}
	for _, ca := range doc.CAs {
		out[ca.Fingerprint] = true
	}
	return out
}

func reportErr(err error) {
	if err != nil {
		fail(err.Error())
	}
}

func must(err error) {
	if err != nil {
		fail(err.Error())
	}
}

func must2(cond bool, msg string) {
	if !cond {
		fail(msg)
	}
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "FAILED: "+msg)
	os.Exit(1)
}
