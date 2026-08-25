# Registration policy fragment: platform component images (container images).
#
# Jointly-agreed criteria between the asset provider and the solution provider.
# A container image is registered only if ALL hold:
#   1. trusted identity  -- signed under the pinned did:x509 code-signing issuer
#   2. container digest   -- CWT 'sub' claim carries the image digest
#   3. SBOM               -- payload declares an 'sbom_digest'
#   4. version            -- non-negative software version number (_svn)
#
# The artefact type is selected by the leaf signing EKU baked into the issuer;
# the content-type (cty) is used only to scope error messages to this type.
#
# The issuer string below is filled in by build_policy.py with the concrete
# did:x509 issuer of the platform release CA.

component_issuer := "__COMPONENT_ISSUER__"
component_cty := "application/vnd.ts.component+json"

# The submission payload is a JSON document, delivered to Rego as a hex string.
component_claim := json.unmarshal(hex.decode(input.payload))

component_trusted if input.phdr["CWT Claims"].iss == component_issuer

component_has_digest if input.phdr["CWT Claims"].sub != ""

component_has_sbom if component_claim.sbom_digest != ""

component_versioned if input.phdr["CWT Claims"]._svn >= 0

component_allowed if {
	component_trusted
	component_has_digest
	component_has_sbom
	component_versioned
}

allow if component_allowed

# Content-type-scoped error reasons, so a denied component submission reports
# exactly which agreed term it failed.
known_cty if input.phdr.cty == component_cty

errors contains "component image: untrusted identity (issuer is not the agreed platform code-signing CA)" if {
	input.phdr.cty == component_cty
	not component_trusted
}

errors contains "component image: missing container image digest (CWT 'sub' claim)" if {
	input.phdr.cty == component_cty
	not component_has_digest
}

errors contains "component image: missing required SBOM ('sbom_digest' in payload)" if {
	input.phdr.cty == component_cty
	not component_has_sbom
}
