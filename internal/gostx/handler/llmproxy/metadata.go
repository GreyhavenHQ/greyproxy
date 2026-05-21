package llmproxy

import (
	mdata "github.com/greyhavenhq/greyproxy/internal/gostcore/metadata"
	mdutil "github.com/greyhavenhq/greyproxy/internal/gostx/metadata/util"
)

// metadata captures handler.type=llmproxy YAML knobs.
//
//	metadata:
//	  auth.require: false      # require Authorization: Bearer <key>
//	  auth.keys:   ["sk-xxx"]  # accepted bearer keys (set when require=true)
type metadata struct {
	authRequire bool
	authKeys    []string
}

func parseMetadata(md mdata.Metadata) metadata {
	return metadata{
		authRequire: mdutil.GetBool(md, "auth.require"),
		authKeys:    mdutil.GetStrings(md, "auth.keys"),
	}
}
