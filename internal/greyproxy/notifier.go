package greyproxy

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/greyhavenhq/greyproxy/internal/gostcore/logger"
)

// Notifier sends OS desktop notifications for pending requests when no
// dashboard tab is focused. It notifies in two cases:
//   - A brand new pending request is created (EventPendingCreated).
//   - A pending request that had zero waiting connections just got one
//     (EventWaitersChanged with PreviousCount==0), provided it was not
//     already notified about in the last 30 seconds.
//
// When a pending request is allowed or dismissed, the notify-send process
// is killed (SIGINT), which closes the desktop notification.
type Notifier struct {
	bus     *EventBus
	db      *DB
	log     logger.Logger
	enabled atomic.Bool

	// Dashboard URL for click-to-open actions.
	dashboardURL string

	// Which notification backend to use (detected at startup).
	backend notifyBackend

	// Presence tracking: focused WS clients.
	focusedMu sync.RWMutex
	focused   map[string]bool // clientID -> focused

	// Track when we last notified per pending key (container|host|port),
	// so we can suppress rapid re-notifications.
	lastNotifiedMu sync.Mutex
	lastNotified   map[string]time.Time

	// Active notify-send processes, keyed by pending ID.
	// Killing the process with SIGINT closes the desktop notification.
	activeNotifMu sync.Mutex
	activeNotif   map[int64]*os.Process

	stop chan struct{}
}

const notifyCooldown = 30 * time.Second

type notifyBackend int

const (
	backendNone notifyBackend = iota
	backendNotifySend
	backendOsascript
)

func NewNotifier(bus *EventBus, db *DB, enabled bool, dashboardURL string) *Notifier {
	n := &Notifier{
		bus:          bus,
		db:           db,
		log:          logger.Default().WithFields(map[string]any{"kind": "notifier"}),
		dashboardURL: dashboardURL,
		focused:      make(map[string]bool),
		lastNotified: make(map[string]time.Time),
		activeNotif:  make(map[int64]*os.Process),
		stop:         make(chan struct{}),
	}
	n.enabled.Store(enabled)
	n.backend = detectBackend()
	return n
}

func detectBackend() notifyBackend {
	switch runtime.GOOS {
	case "linux":
		if _, err := exec.LookPath("notify-send"); err == nil {
			return backendNotifySend
		}
	case "darwin":
		if _, err := exec.LookPath("osascript"); err == nil {
			return backendOsascript
		}
	}
	return backendNone
}

// Start begins listening for events.
func (n *Notifier) Start() {
	if n.backend == backendNone {
		n.log.Warn("no notification backend found (install libnotify on Linux); desktop notifications disabled")
		n.enabled.Store(false)
	}

	ch := n.bus.Subscribe(128)

	go func() {
		defer n.bus.Unsubscribe(ch)
		for {
			select {
			case evt, ok := <-ch:
				if !ok {
					return
				}
				switch evt.Type {
				case EventPendingCreated:
					n.onPendingCreated(evt)
				case EventWaitersChanged:
					n.onWaitersChanged(evt)
				case EventPendingAllowed, EventPendingDismissed:
					n.onPendingResolved(evt)
				}
			case <-n.stop:
				return
			}
		}
	}()

	// Periodic cleanup of stale tracking entries.
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				n.cleanupTracking()
			case <-n.stop:
				return
			}
		}
	}()

	n.log.Infof("notifier started (enabled=%v, backend=%v)", n.enabled.Load(), n.backendName())
}

func (n *Notifier) backendName() string {
	switch n.backend {
	case backendNotifySend:
		return "notify-send"
	case backendOsascript:
		return "osascript"
	default:
		return "none"
	}
}

// Stop shuts down the notifier and closes all active notifications.
func (n *Notifier) Stop() {
	close(n.stop)
	n.closeAllNotifications()
}

// SetEnabled toggles notifications on/off.
func (n *Notifier) SetEnabled(v bool) {
	if v && n.backend == backendNone {
		n.log.Warn("cannot enable notifications: no backend available")
		return
	}
	n.enabled.Store(v)
	n.log.Infof("notifications %s", map[bool]string{true: "enabled", false: "disabled"}[v])
}

// Enabled returns whether notifications are on.
func (n *Notifier) Enabled() bool {
	return n.enabled.Load()
}

// SetClientFocused updates the focus state for a WS client.
func (n *Notifier) SetClientFocused(clientID string, focused bool) {
	n.focusedMu.Lock()
	defer n.focusedMu.Unlock()
	n.focused[clientID] = focused
}

// RemoveClient removes a WS client from presence tracking.
func (n *Notifier) RemoveClient(clientID string) {
	n.focusedMu.Lock()
	defer n.focusedMu.Unlock()
	delete(n.focused, clientID)
}

func (n *Notifier) hasAnyFocusedClient() bool {
	n.focusedMu.RLock()
	defer n.focusedMu.RUnlock()
	for _, f := range n.focused {
		if f {
			return true
		}
	}
	return false
}

// onPendingCreated handles a brand new pending request; always notify.
func (n *Notifier) onPendingCreated(evt Event) {
	if !n.shouldNotify() {
		return
	}

	data, ok := evt.Data.(PendingRequestJSON)
	if !ok {
		return
	}

	key := pendingKey(data.ContainerName, data.DestinationHost, data.DestinationPort)
	n.recordNotified(key)

	n.log.Infof("notification: new pending %d (%s)", data.ID, key)
	n.sendPendingNotification(data)
}

// onWaitersChanged handles when a pending goes from 0 waiters to 1+.
func (n *Notifier) onWaitersChanged(evt Event) {
	if !n.shouldNotify() {
		return
	}

	data, ok := evt.Data.(WaiterChangedData)
	if !ok || data.PreviousCount != 0 {
		return
	}

	key := pendingKey(data.ContainerName, data.Host, data.Port)

	n.lastNotifiedMu.Lock()
	last, exists := n.lastNotified[key]
	n.lastNotifiedMu.Unlock()

	if exists && time.Since(last) < notifyCooldown {
		return
	}

	n.recordNotified(key)

	pending := FindPendingByDestination(n.db, data.ContainerName, data.Host, data.Port)
	if pending == nil {
		return
	}

	n.log.Infof("notification: waiter resumed for pending %d (%s)", pending.ID, key)
	n.sendPendingNotification(pending.ToJSON())
}

// onPendingResolved closes the desktop notification for a pending that
// was just allowed or dismissed.
func (n *Notifier) onPendingResolved(evt Event) {
	data, ok := evt.Data.(map[string]any)
	if !ok {
		return
	}
	id, ok := data["pending_id"]
	if !ok {
		return
	}

	var pendingID int64
	switch v := id.(type) {
	case int64:
		pendingID = v
	case float64:
		pendingID = int64(v)
	case int:
		pendingID = int64(v)
	default:
		return
	}

	n.log.Debugf("pending %d resolved (%s)", pendingID, evt.Type)
	n.closeNotification(pendingID)
}

func (n *Notifier) shouldNotify() bool {
	if !n.enabled.Load() {
		return false
	}
	if n.hasAnyFocusedClient() {
		return false
	}
	return true
}

func (n *Notifier) recordNotified(key string) {
	n.lastNotifiedMu.Lock()
	n.lastNotified[key] = time.Now()
	n.lastNotifiedMu.Unlock()
}

func (n *Notifier) sendPendingNotification(data PendingRequestJSON) {
	host := data.DestinationHost
	if data.ResolvedHostname != nil && *data.ResolvedHostname != "" {
		host = *data.ResolvedHostname
	}
	body := fmt.Sprintf("%s wants to connect to %s:%d", data.ContainerName, host, data.DestinationPort)
	url := fmt.Sprintf("%s?highlight=%d", n.dashboardURL, data.ID)
	n.sendNotification("GreyProxy", body, url, data.ID)
}

func pendingKey(container, host string, port int) string {
	return fmt.Sprintf("%s|%s|%d", container, host, port)
}

// cleanupTracking removes entries older than 2x the cooldown.
func (n *Notifier) cleanupTracking() {
	cutoff := time.Now().Add(-2 * notifyCooldown)
	n.lastNotifiedMu.Lock()
	defer n.lastNotifiedMu.Unlock()
	for key, t := range n.lastNotified {
		if t.Before(cutoff) {
			delete(n.lastNotified, key)
		}
	}
}

func (n *Notifier) trackNotification(pendingID int64, proc *os.Process) {
	n.activeNotifMu.Lock()
	defer n.activeNotifMu.Unlock()
	if old, exists := n.activeNotif[pendingID]; exists {
		old.Signal(syscall.SIGINT)
	}
	n.activeNotif[pendingID] = proc
	n.log.Debugf("tracked pid %d for pending %d (active: %d)", proc.Pid, pendingID, len(n.activeNotif))
}

func (n *Notifier) untrackNotification(pendingID int64) {
	n.activeNotifMu.Lock()
	defer n.activeNotifMu.Unlock()
	delete(n.activeNotif, pendingID)
}

// closeNotification sends SIGINT to the notify-send process, which
// causes it to clean up and close the desktop notification.
func (n *Notifier) closeNotification(pendingID int64) {
	n.activeNotifMu.Lock()
	proc, exists := n.activeNotif[pendingID]
	if exists {
		delete(n.activeNotif, pendingID)
	}
	n.activeNotifMu.Unlock()

	if exists && proc != nil {
		n.log.Infof("closing notification for pending %d (pid %d)", pendingID, proc.Pid)
		proc.Signal(syscall.SIGINT)
	}
}

func (n *Notifier) closeAllNotifications() {
	n.activeNotifMu.Lock()
	defer n.activeNotifMu.Unlock()
	for _, proc := range n.activeNotif {
		if proc != nil {
			proc.Signal(syscall.SIGINT)
		}
	}
	n.activeNotif = make(map[int64]*os.Process)
}

func (n *Notifier) sendNotification(title, body, url string, pendingID int64) {
	switch n.backend {
	case backendNotifySend:
		n.sendLinux(title, body, url, pendingID)
	case backendOsascript:
		n.sendDarwin(title, body, url)
	}
}

func (n *Notifier) sendLinux(title, body, url string, pendingID int64) {
	go func() {
		cmd := exec.Command("notify-send",
			"-a", "greyproxy",
			"-u", "normal",
			"-c", "network",
			"-t", "30000",
			"-w",
			"--action=default=Open Dashboard",
			title,
			body,
		)

		stdout, err := cmd.StdoutPipe()
		if err != nil {
			n.log.Debugf("notify-send pipe: %v", err)
			return
		}

		if err := cmd.Start(); err != nil {
			n.log.Debugf("notify-send start: %v", err)
			return
		}

		n.trackNotification(pendingID, cmd.Process)

		// Read action output (blocks until notification is closed or clicked).
		scanner := bufio.NewScanner(stdout)
		if scanner.Scan() {
			action := strings.TrimSpace(scanner.Text())
			if action == "default" {
				exec.Command("xdg-open", url).Start()
			}
		}

		cmd.Wait()
		n.untrackNotification(pendingID)
	}()
}

func (n *Notifier) sendDarwin(title, body, url string) {
	script := fmt.Sprintf(`display notification %q with title %q`, body, title)
	go func() {
		cmd := exec.Command("osascript", "-e", script)
		if err := cmd.Run(); err != nil {
			n.log.Debugf("osascript: %v", err)
		}
	}()
}
