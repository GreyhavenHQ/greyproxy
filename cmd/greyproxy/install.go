package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/kardianos/service"
	flag "github.com/spf13/pflag"
)

const serviceName = "greyproxy"

func parseInstallFlags(args []string) (force bool) {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	fs.BoolVarP(&force, "force", "f", false, "skip confirmation prompts")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	return
}

func installBinPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "bin", "greyproxy")
}

func serviceLabel() string {
	if runtime.GOOS == "darwin" {
		return "launchd user agent"
	}
	return "systemd user service"
}

// isBrewManaged returns true if the given binary path lives under the
// Homebrew prefix (e.g. /opt/homebrew or /usr/local).
func isBrewManaged(binPath string) bool {
	if runtime.GOOS != "darwin" {
		return false
	}
	out, err := exec.Command("brew", "--prefix").Output()
	if err != nil {
		return false
	}
	prefix := strings.TrimSpace(string(out))
	if prefix == "" {
		return false
	}
	return strings.HasPrefix(binPath, prefix)
}

func newServiceConfig(execPath string) *service.Config {
	return &service.Config{
		Name:        serviceName,
		DisplayName: "Greyproxy",
		Description: "Greyproxy network proxy service",
		Executable:  execPath,
		Arguments:   []string{"serve"},
		Option: service.KeyValue{
			"UserService": true,
		},
	}
}

func newServiceControl() (service.Service, error) {
	return service.New(&program{}, newServiceConfig(installBinPath()))
}

func newServiceControlAt(execPath string) (service.Service, error) {
	return service.New(&program{}, newServiceConfig(execPath))
}

func isInstalled() bool {
	_, err := os.Stat(installBinPath())
	return err == nil
}

func handleInstall(args []string) {
	force := parseInstallFlags(args)

	binSrc, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot determine current executable: %v\n", err)
		os.Exit(1)
	}
	binSrc, _ = filepath.EvalSymlinks(binSrc)

	// When installed via Homebrew, skip the binary copy and register the
	// service pointing at the brew-managed binary directly. This way
	// "brew upgrade" keeps the running service up to date.
	if isBrewManaged(binSrc) {
		handleBrewInstall(binSrc, force)
		return
	}

	binDst := installBinPath()

	if isInstalled() {
		handleReinstall(binSrc, binDst, force)
		return
	}

	label := serviceLabel()
	fmt.Printf("Ready to install greyproxy. This will:\n")
	fmt.Printf("  1. Copy %s -> %s\n", binSrc, binDst)
	fmt.Printf("  2. Register greyproxy as a %s\n", label)
	fmt.Printf("  3. Start the service\n")

	if !force {
		fmt.Printf("\nProceed? [Y/n] ")
		if !askConfirm() {
			fmt.Println("You can start the server manually with: greyproxy serve")
			fmt.Println("Dashboard: http://localhost:43080")
			return
		}
	}

	freshInstall(binSrc, binDst)
	fmt.Println("\nDashboard: http://localhost:43080")
}

func handleBrewInstall(brewBin string, force bool) {
	label := serviceLabel()
	fmt.Printf("Homebrew installation detected at %s\n", brewBin)
	fmt.Printf("\nThis will register the brew-managed binary as a %s.\n", label)
	fmt.Printf("Future upgrades via 'brew upgrade greyproxy' will keep the service current.\n")

	if !force {
		fmt.Printf("\nProceed? [Y/n] ")
		if !askConfirm() {
			fmt.Println("You can start the server manually with: greyproxy serve")
			fmt.Println("Dashboard: http://localhost:43080")
			return
		}
	}

	// Stop and unregister any existing service (may point at ~/.local/bin)
	if s, err := newServiceControl(); err == nil {
		_ = service.Control(s, "stop")
		_ = service.Control(s, "uninstall")
	}

	s, err := newServiceControlAt(brewBin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if err := service.Control(s, "install"); err != nil {
		fmt.Fprintf(os.Stderr, "error: registering service: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Registered %s\n", label)

	if err := service.Control(s, "start"); err != nil {
		fmt.Fprintf(os.Stderr, "error: starting service: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Service started")
	fmt.Println("\nDashboard: http://localhost:43080")
}

func handleReinstall(binSrc, binDst string, force bool) {
	label := serviceLabel()
	fmt.Printf("An existing installation was found at %s\n", binDst)
	fmt.Printf("\nReady to update the existing installation. This will:\n")
	fmt.Printf("  1. Stop the running service\n")
	fmt.Printf("  2. Remove the current service registration\n")
	fmt.Printf("  3. Replace the binary with %s\n", binSrc)
	fmt.Printf("  4. Re-register the %s\n", label)
	fmt.Printf("  5. Start the service\n")

	if !force {
		fmt.Printf("\nProceed? [Y/n] ")
		if !askConfirm() {
			fmt.Println("You can start the server manually with: greyproxy serve")
			fmt.Println("Dashboard: http://localhost:43080")
			return
		}
	}

	s, err := newServiceControl()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// 1. Stop service (ignore error -- may already be stopped)
	_ = service.Control(s, "stop")
	fmt.Println("Service stopped")

	// 2. Unregister old service (ignore error -- may not be registered)
	_ = service.Control(s, "uninstall")
	fmt.Println("Removed old service registration")

	// 3-5. Fresh install (copy binary, register, start)
	freshInstall(binSrc, binDst)
	fmt.Println("\nDashboard: http://localhost:43080")
}

func freshInstall(binSrc, binDst string) {
	label := serviceLabel()

	// Copy binary
	if err := copyBinary(binSrc, binDst); err != nil {
		fmt.Fprintf(os.Stderr, "error: copying binary: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Installed binary to %s\n", binDst)

	// Register service
	s, err := newServiceControl()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if err := service.Control(s, "install"); err != nil {
		fmt.Fprintf(os.Stderr, "error: registering service: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Registered %s\n", label)

	// Start service
	if err := service.Control(s, "start"); err != nil {
		fmt.Fprintf(os.Stderr, "error: starting service: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Service started")
}

func askConfirm() bool {
	var answer string
	fmt.Scanln(&answer)
	if answer == "n" || answer == "N" {
		fmt.Println("Aborted.")
		return false
	}
	return true
}

func handleUninstall(args []string) {
	force := parseInstallFlags(args)
	binDst := installBinPath()
	label := serviceLabel()

	certInstalled := isCertInstalled()

	fmt.Printf("Ready to uninstall greyproxy. This will:\n")
	fmt.Printf("  1. Stop the greyproxy service\n")
	fmt.Printf("  2. Remove the %s\n", label)
	fmt.Printf("  3. Remove %s\n", binDst)
	if certInstalled {
		fmt.Printf("  4. Remove CA certificate from system trust store\n")
	}

	if !force {
		fmt.Printf("\nProceed? [Y/n] ")
		if !askConfirm() {
			return
		}
	}

	s, err := newServiceControl()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// 1. Stop service (ignore error -- may already be stopped)
	_ = service.Control(s, "stop")
	fmt.Println("Service stopped")

	// 2. Unregister service
	if err := service.Control(s, "uninstall"); err != nil {
		fmt.Fprintf(os.Stderr, "error: removing service: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Removed %s\n", label)

	// 3. Remove binary
	if err := os.Remove(binDst); err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "error: removing binary: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Removed %s\n", binDst)

	// 4. Remove CA certificate from trust store
	if certInstalled {
		handleCertUninstall()
	}
}

func copyBinary(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}

	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}
