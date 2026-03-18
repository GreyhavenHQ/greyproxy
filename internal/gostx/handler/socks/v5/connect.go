package v5

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/greyhavenhq/greyproxy/internal/gostcore/bypass"
	"github.com/greyhavenhq/greyproxy/internal/gostcore/limiter"
	"github.com/greyhavenhq/greyproxy/internal/gostcore/logger"
	"github.com/greyhavenhq/greyproxy/internal/gostcore/observer/stats"
	"github.com/greyhavenhq/greyproxy/internal/gosocks5"
	gostx "github.com/greyhavenhq/greyproxy/internal/gostx"
	xctx "github.com/greyhavenhq/greyproxy/internal/gostx/ctx"
	ictx "github.com/greyhavenhq/greyproxy/internal/gostx/internal/ctx"
	xnet "github.com/greyhavenhq/greyproxy/internal/gostx/internal/net"
	"github.com/greyhavenhq/greyproxy/internal/gostx/internal/util/sniffing"
	traffic_wrapper "github.com/greyhavenhq/greyproxy/internal/gostx/limiter/traffic/wrapper"
	stats_wrapper "github.com/greyhavenhq/greyproxy/internal/gostx/observer/stats/wrapper"
	xrecorder "github.com/greyhavenhq/greyproxy/internal/gostx/recorder"
)

func (h *socks5Handler) handleConnect(ctx context.Context, conn net.Conn, network, address string, ro *xrecorder.HandlerRecorderObject, log logger.Logger) error {
	log = log.WithFields(map[string]any{
		"dst":  fmt.Sprintf("%s/%s", address, network),
		"cmd":  "connect",
		"host": address,
	})
	log.Debugf("%s >> %s", conn.RemoteAddr(), address)

	{
		clientID := xctx.ClientIDFromContext(ctx)
		rw := traffic_wrapper.WrapReadWriter(
			h.limiter,
			conn,
			string(clientID),
			limiter.ServiceOption(h.options.Service),
			limiter.ScopeOption(limiter.ScopeClient),
			limiter.NetworkOption(network),
			limiter.AddrOption(address),
			limiter.ClientOption(string(clientID)),
			limiter.SrcOption(conn.RemoteAddr().String()),
		)
		if h.options.Observer != nil {
			pstats := h.stats.Stats(string(clientID))
			pstats.Add(stats.KindTotalConns, 1)
			pstats.Add(stats.KindCurrentConns, 1)
			defer pstats.Add(stats.KindCurrentConns, -1)
			rw = stats_wrapper.WrapReadWriter(rw, pstats)
		}

		conn = xnet.NewReadWriteConn(rw, rw, conn)
	}

	if h.options.Bypass != nil {
		bypassResult := &xctx.BypassResult{}
		resultCtx := xctx.ContextWithBypassResult(ctx, bypassResult)
		bypassCtx, bypassCancel := context.WithCancel(resultCtx)

		// Monitor the client TCP connection for close during the bypass check.
		// During SOCKS5 CONNECT, the client waits for the server reply before
		// sending data (RFC 1928), so no legitimate data arrives here.
		monitorDone := make(chan struct{})
		go func() {
			defer close(monitorDone)
			buf := make([]byte, 1)
			for {
				conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				_, err := conn.Read(buf)
				if err == nil {
					continue
				}
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					select {
					case <-bypassCtx.Done():
						return
					default:
						continue
					}
				}
				// Real error (connection closed)
				bypassCancel()
				return
			}
		}()

		blocked := h.options.Bypass.Contains(bypassCtx, network, address, bypass.WithService(h.options.Service))
		bypassCancel()
		<-monitorDone
		conn.SetReadDeadline(time.Time{}) // reset deadline

		if blocked {
			resp := gosocks5.NewReply(gosocks5.NotAllowed, nil)
			log.Trace(resp)
			log.Debug("bypass: ", address)
			return resp.Write(conn)
		}

		// Register this connection for cancellation if the rule is later deleted.
		if bypassResult.RuleID != 0 && bypassResult.Tracker != nil {
			var pipeCancel context.CancelFunc
			ctx, pipeCancel = context.WithCancel(ctx)
			connID := bypassResult.Tracker.Register(bypassResult.RuleID, pipeCancel)
			defer func() {
				bypassResult.Tracker.Unregister(bypassResult.RuleID, connID)
				pipeCancel()
			}()
		}
	}

	switch h.md.hash {
	case "host":
		ctx = xctx.ContextWithHash(ctx, &xctx.Hash{Source: address})
	}

	var buf bytes.Buffer
	cc, err := h.options.Router.Dial(ictx.ContextWithBuffer(ctx, &buf), network, address)
	ro.Route = buf.String()
	if err != nil {
		resp := gosocks5.NewReply(gosocks5.NetUnreachable, nil)
		log.Trace(resp)
		resp.Write(conn)
		return err
	}
	defer cc.Close()

	log = log.WithFields(map[string]any{"src": cc.LocalAddr().String(), "dst": cc.RemoteAddr().String()})
	ro.SrcAddr = cc.LocalAddr().String()
	ro.DstAddr = cc.RemoteAddr().String()

	resp := gosocks5.NewReply(gosocks5.Succeeded, nil)
	log.Trace(resp)
	if err := resp.Write(conn); err != nil {
		log.Error(err)
		return err
	}

	if h.md.sniffing {
		if h.md.sniffingTimeout > 0 {
			conn.SetReadDeadline(time.Now().Add(h.md.sniffingTimeout))
		}

		br := bufio.NewReader(conn)
		proto, _ := sniffing.Sniff(ctx, br)
		ro.Proto = proto

		if h.md.sniffingTimeout > 0 {
			conn.SetReadDeadline(time.Time{})
		}

		dial := func(ctx context.Context, network, address string) (net.Conn, error) {
			return cc, nil
		}
		dialTLS := func(ctx context.Context, network, address string, cfg *tls.Config) (net.Conn, error) {
			return cc, nil
		}
		sniffer := &sniffing.Sniffer{
			Websocket:           h.md.sniffingWebsocket,
			WebsocketSampleRate: h.md.sniffingWebsocketSampleRate,
			Recorder:            h.recorder.Recorder,
			RecorderOptions:     h.recorder.Options,
			Certificate:         h.md.certificate,
			PrivateKey:          h.md.privateKey,
			NegotiatedProtocol:  h.md.alpn,
			CertPool:            h.certPool,
			MitmBypass:          h.md.mitmBypass,
			ReadTimeout:         h.md.readTimeout,
			OnHTTPRoundTrip:     mitmLogHook(log),
			OnMitmSkip: func() {
				if hook := gostx.GlobalConnectionFinishHook; hook != nil {
					hook(gostx.ConnectionFinishInfo{
						Host:           ro.Host,
						MitmSkipReason: ro.MitmSkipReason,
						ContainerName:  ro.ClientID,
					})
				}
			},
		}

		conn = xnet.NewReadWriteConn(br, conn, conn)
		switch proto {
		case sniffing.ProtoHTTP:
			return sniffer.HandleHTTP(ctx, "tcp", conn,
				sniffing.WithService(h.options.Service),
				sniffing.WithDial(dial),
				sniffing.WithDialTLS(dialTLS),
				sniffing.WithRecorderObject(ro),
				sniffing.WithLog(log),
			)
		case sniffing.ProtoTLS:
			if err := sniffer.HandleTLS(ctx, "tcp", conn,
				sniffing.WithService(h.options.Service),
				sniffing.WithDial(dial),
				sniffing.WithDialTLS(dialTLS),
				sniffing.WithRecorderObject(ro),
				sniffing.WithLog(log),
			); err != nil {
				if ro.MitmSkipReason == "" {
					ro.MitmSkipReason = "mitm_error"
				}
				return err
			}
			return nil
		default:
			ro.MitmSkipReason = "non_tls"
		}
	} else {
		ro.MitmSkipReason = "sniffing_disabled"
	}

	t := time.Now()
	log.Infof("%s <-> %s", conn.RemoteAddr(), address)
	// xnet.Transport(conn, cc)
	xnet.Pipe(ctx, conn, cc)
	log.WithFields(map[string]any{
		"duration": time.Since(t),
	}).Infof("%s >-< %s", conn.RemoteAddr(), address)

	return nil
}

func mitmLogHook(log logger.Logger) func(info sniffing.HTTPRoundTripInfo) {
	return func(info sniffing.HTTPRoundTripInfo) {
		log.Infof("[MITM] %s %s%s → %d", info.Method, info.Host, info.URI, info.StatusCode)
		log.Debugf("[MITM] Request Headers: %v", info.RequestHeaders)
		if len(info.RequestBody) > 0 {
			log.Debugf("[MITM] Request Body: %s", info.RequestBody)
		}
		log.Debugf("[MITM] Response Headers: %v", info.ResponseHeaders)
		if len(info.ResponseBody) > 0 {
			bodyPreview := info.ResponseBody
			if len(bodyPreview) > 512 {
				bodyPreview = bodyPreview[:512]
			}
			log.Debugf("[MITM] Response Body (%d bytes): %s", len(info.ResponseBody), bodyPreview)
		}
	}
}
