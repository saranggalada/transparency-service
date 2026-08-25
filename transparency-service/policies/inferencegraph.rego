# Registration policy fragment: InferenceGraph definitions.
#
# An InferenceGraph is registered only if:
#   1. trusted identity -- signed under the pinned Inference Provider did:x509 issuer
#   2. graph digest     -- CWT 'sub' claim carries the graph definition hash
#
# The issuer string below is filled in by build_policy.py with the concrete
# did:x509 issuer of the Inference Provider CA + graph-signing EKU.

inferencegraph_issuer := "__INFERENCEGRAPH_ISSUER__"
inferencegraph_cty := "application/vnd.ts.inferencegraph+json"

inferencegraph_trusted if input.phdr["CWT Claims"].iss == inferencegraph_issuer

inferencegraph_has_digest if input.phdr["CWT Claims"].sub != ""

inferencegraph_allowed if {
	inferencegraph_trusted
	inferencegraph_has_digest
	# extend: structural validation of the declared nodes/edges against the
	# InferenceService topology, parsed from the payload via
	# json.unmarshal(hex.decode(input.payload)).
}

allow if inferencegraph_allowed

known_cty if input.phdr.cty == inferencegraph_cty

errors contains "inferencegraph: untrusted identity (issuer is not the agreed Inference Provider CA)" if {
	input.phdr.cty == inferencegraph_cty
	not inferencegraph_trusted
}

errors contains "inferencegraph: missing graph digest (CWT 'sub' claim)" if {
	input.phdr.cty == inferencegraph_cty
	not inferencegraph_has_digest
}
