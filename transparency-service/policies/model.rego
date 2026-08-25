# Registration policy fragment: AI model weights.
#
# A model artefact is registered only if:
#   1. trusted identity -- signed under the pinned Inference Provider did:x509 issuer
#   2. weight digest    -- CWT 'sub' claim carries the weight-file hash
#
# The issuer string below is filled in by build_policy.py with the concrete
# did:x509 issuer of the Inference Provider CA + model-signing EKU.

model_issuer := "__MODEL_ISSUER__"
model_cty := "application/vnd.ts.model+json"

model_trusted if input.phdr["CWT Claims"].iss == model_issuer

model_has_digest if input.phdr["CWT Claims"].sub != ""

model_allowed if {
	model_trusted
	model_has_digest
	# extend: require a safe weight-file format claim (e.g. safetensors, not
	# pickle), provenance / training-data or license claims, parsed from the
	# payload via json.unmarshal(hex.decode(input.payload)).
}

allow if model_allowed

known_cty if input.phdr.cty == model_cty

errors contains "model: untrusted identity (issuer is not the agreed Inference Provider CA)" if {
	input.phdr.cty == model_cty
	not model_trusted
}

errors contains "model: missing weight-file digest (CWT 'sub' claim)" if {
	input.phdr.cty == model_cty
	not model_has_digest
}
