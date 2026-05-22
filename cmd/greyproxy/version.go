package main

// Build-time variables (set via -ldflags)
var (
	// version is reported by /api/health. Bumped to 0.5.0 to satisfy
	// greywall's proxy.MinVersionFsEvents gate so --record-fs heartbeats
	// are shipped instead of being silently downgraded.
	version   = "0.5.0"
	buildTime = "unknown"
	gitCommit = "unknown"
)
