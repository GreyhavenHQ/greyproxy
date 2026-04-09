package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/greyhavenhq/greyproxy/internal/gostcore/logger"
	greyproxy "github.com/greyhavenhq/greyproxy/internal/greyproxy"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func randomClientID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

type wsClient struct {
	id            string
	conn          *websocket.Conn
	mu            sync.Mutex
	subscriptions map[string]bool // nil means "subscribe to all"
	subMu         sync.RWMutex
}

func (c *wsClient) send(msg any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn.WriteJSON(msg)
}

// shouldReceive checks if the client is subscribed to the given event type.
// If no subscriptions are set (nil map), all events are forwarded.
func (c *wsClient) shouldReceive(eventType string) bool {
	c.subMu.RLock()
	defer c.subMu.RUnlock()
	if c.subscriptions == nil {
		return true // No filter — receive everything
	}
	return c.subscriptions[eventType]
}

func (c *wsClient) subscribe(eventType string) {
	c.subMu.Lock()
	defer c.subMu.Unlock()
	if c.subscriptions == nil {
		c.subscriptions = make(map[string]bool)
	}
	c.subscriptions[eventType] = true
}

func (c *wsClient) unsubscribe(eventType string) {
	c.subMu.Lock()
	defer c.subMu.Unlock()
	if c.subscriptions != nil {
		delete(c.subscriptions, eventType)
	}
}

func WebSocketHandler(s *Shared) gin.HandlerFunc {
	log := logger.Default().WithFields(map[string]any{"kind": "websocket"})

	return func(c *gin.Context) {
		conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
		if err != nil {
			log.Errorf("websocket upgrade: %v", err)
			return
		}
		defer func() { _ = conn.Close() }()

		client := &wsClient{id: randomClientID(), conn: conn}

		// Send connected message
		_ = client.send(gin.H{
			"type":      "connected",
			"message":   "Connected to proxy event stream",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		})

		// Subscribe to events
		ch := s.Bus.Subscribe(128)
		defer s.Bus.Unsubscribe(ch)

		// Read commands from client in a goroutine
		done := make(chan struct{})
		go func() {
			defer close(done)
			handleClientCommands(client, s, log)
		}()

		// Forward events to client (filtered by subscriptions)
		for {
			select {
			case evt, ok := <-ch:
				if !ok {
					return
				}
				if client.shouldReceive(evt.Type) {
					if err := client.send(evt); err != nil {
						log.Debugf("ws send error: %v", err)
						return
					}
				}
			case <-done:
				return
			}
		}
	}
}

type wsCommand struct {
	Command   string `json:"command"`
	PendingID int64  `json:"pending_id"`
	Scope     string `json:"scope"`
	Duration  string `json:"duration"`
	Notes     string `json:"notes"`
	EventType string `json:"event_type"` // For subscribe/unsubscribe
}

func handleClientCommands(client *wsClient, s *Shared, log logger.Logger) {
	for {
		_, message, err := client.conn.ReadMessage()
		if err != nil {
			return
		}

		var cmd wsCommand
		if err := json.Unmarshal(message, &cmd); err != nil {
			_ = client.send(gin.H{
				"type":      "error",
				"error":     "invalid JSON",
				"timestamp": time.Now().UTC().Format(time.RFC3339),
			})
			continue
		}

		switch cmd.Command {
		case "ping":
			_ = client.send(gin.H{
				"type":      "pong",
				"timestamp": time.Now().UTC().Format(time.RFC3339),
			})

		case "allow":
			scope := cmd.Scope
			if scope == "" {
				scope = "exact"
			}
			duration := cmd.Duration
			if duration == "" {
				duration = "permanent"
			}
			var notes *string
			if cmd.Notes != "" {
				notes = &cmd.Notes
			}

			rule, err := greyproxy.AllowPending(s.DB, cmd.PendingID, scope, duration, notes)
			if err != nil {
				_ = client.send(gin.H{
					"type":      "error",
					"error":     err.Error(),
					"timestamp": time.Now().UTC().Format(time.RFC3339),
				})
				continue
			}

			s.Bus.Publish(greyproxy.Event{
				Type: greyproxy.EventPendingAllowed,
				Data: gin.H{"pending_id": cmd.PendingID, "rule": rule.ToJSON()},
			})

			_ = client.send(gin.H{
				"type":       "command_success",
				"command":    "allow",
				"pending_id": cmd.PendingID,
				"rule_id":    rule.ID,
				"timestamp":  time.Now().UTC().Format(time.RFC3339),
			})

		case "dismiss":
			ok, err := greyproxy.DeletePending(s.DB, cmd.PendingID)
			if err != nil || !ok {
				errMsg := "pending request not found"
				if err != nil {
					errMsg = err.Error()
				}
				_ = client.send(gin.H{
					"type":      "error",
					"error":     errMsg,
					"timestamp": time.Now().UTC().Format(time.RFC3339),
				})
				continue
			}

			s.Bus.Publish(greyproxy.Event{
				Type: greyproxy.EventPendingDismissed,
				Data: gin.H{"pending_id": cmd.PendingID},
			})

			_ = client.send(gin.H{
				"type":       "command_success",
				"command":    "dismiss",
				"pending_id": cmd.PendingID,
				"timestamp":  time.Now().UTC().Format(time.RFC3339),
			})

		case "subscribe":
			if cmd.EventType == "" {
				_ = client.send(gin.H{
					"type":      "error",
					"error":     "event_type is required for subscribe",
					"timestamp": time.Now().UTC().Format(time.RFC3339),
				})
				continue
			}
			client.subscribe(cmd.EventType)
			_ = client.send(gin.H{
				"type":       "subscribed",
				"event_type": cmd.EventType,
				"timestamp":  time.Now().UTC().Format(time.RFC3339),
			})

		case "unsubscribe":
			if cmd.EventType == "" {
				_ = client.send(gin.H{
					"type":      "error",
					"error":     "event_type is required for unsubscribe",
					"timestamp": time.Now().UTC().Format(time.RFC3339),
				})
				continue
			}
			client.unsubscribe(cmd.EventType)
			_ = client.send(gin.H{
				"type":       "unsubscribed",
				"event_type": cmd.EventType,
				"timestamp":  time.Now().UTC().Format(time.RFC3339),
			})

		default:
			_ = client.send(gin.H{
				"type":      "error",
				"error":     "unknown command: " + cmd.Command,
				"timestamp": time.Now().UTC().Format(time.RFC3339),
			})
		}
	}
}
