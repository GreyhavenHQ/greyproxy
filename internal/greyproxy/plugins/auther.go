package plugins

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/greyhavenhq/greyproxy/internal/gostcore/auth"
	"github.com/greyhavenhq/greyproxy/internal/gostcore/logger"
	xctx "github.com/greyhavenhq/greyproxy/internal/gostx/ctx"
)

// Auther implements auth.Authenticator.
// It always authenticates successfully and returns a composite ID "ip|username".
type Auther struct {
	log logger.Logger
}

func NewAuther() *Auther {
	return &Auther{
		log: logger.Default().WithFields(map[string]any{
			"kind":    "auther",
			"auther":  "greyproxy",
		}),
	}
}

func (a *Auther) Authenticate(ctx context.Context, user, password string, opts ...auth.Option) (id string, ok bool) {
	var options auth.Options
	for _, opt := range opts {
		opt(&options)
	}

	// Extract client IP from the context or service info
	clientIP := extractClientIP(ctx)

	// Build composite ID: "ip|username"
	if user != "" && user != "proxy" {
		id = fmt.Sprintf("%s|%s", clientIP, user)
	} else {
		id = clientIP
	}

	a.log.Debugf("auth: user=%s client=%s -> id=%s", user, clientIP, id)
	return id, true
}

func extractClientIP(ctx context.Context) string {
	// Get source address from context using the canonical key from gostx/ctx
	if addr := xctx.SrcAddrFromContext(ctx); addr != nil {
		host, _, err := net.SplitHostPort(addr.String())
		if err == nil {
			return host
		}
		return addr.String()
	}
	return "unknown"
}

// ParseClientID splits a composite client ID "ip|username" into its components.
func ParseClientID(clientID string) (ip, username string) {
	parts := strings.SplitN(clientID, "|", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return clientID, ""
}
