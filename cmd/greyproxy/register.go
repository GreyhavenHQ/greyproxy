package main

import (
	// SQLite driver for greyproxy
	_ "modernc.org/sqlite"

	// Register connectors
	_ "github.com/greyhavenhq/greyproxy/internal/gostx/connector/direct"
	_ "github.com/greyhavenhq/greyproxy/internal/gostx/connector/http"
	_ "github.com/greyhavenhq/greyproxy/internal/gostx/connector/socks/v5"

	// Register dialers
	_ "github.com/greyhavenhq/greyproxy/internal/gostx/dialer/direct"
	_ "github.com/greyhavenhq/greyproxy/internal/gostx/dialer/tcp"
	_ "github.com/greyhavenhq/greyproxy/internal/gostx/dialer/udp"

	// Register handlers
	_ "github.com/greyhavenhq/greyproxy/internal/gostx/handler/dns"
	_ "github.com/greyhavenhq/greyproxy/internal/gostx/handler/http"
	_ "github.com/greyhavenhq/greyproxy/internal/gostx/handler/llmproxy"
	_ "github.com/greyhavenhq/greyproxy/internal/gostx/handler/socks/v5"

	// Register listeners
	_ "github.com/greyhavenhq/greyproxy/internal/gostx/listener/dns"
	_ "github.com/greyhavenhq/greyproxy/internal/gostx/listener/tcp"
	_ "github.com/greyhavenhq/greyproxy/internal/gostx/listener/udp"
)
