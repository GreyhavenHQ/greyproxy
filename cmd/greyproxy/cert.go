package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

func handleCert(args []string) {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, `Usage: greyproxy cert <command>

Commands:
  generate    Generate CA certificate and key pair
  install     Trust the CA certificate on the OS
  uninstall   Remove the CA certificate from the OS trust store
  reload      Reload the CA certificate in the running greyproxy (no restart needed)

Options:
  -f          Force overwrite existing files (generate, install)
`)
		os.Exit(1)
	}

	switch args[0] {
	case "generate":
		force := len(args) > 1 && args[1] == "-f"
		handleCertGenerate(force)
	case "install":
		force := len(args) > 1 && args[1] == "-f"
		handleCertInstall(force)
	case "uninstall":
		handleCertUninstall()
	case "reload":
		handleCertReload()
	default:
		fmt.Fprintf(os.Stderr, "unknown cert command: %s\n", args[0])
		os.Exit(1)
	}
}

func handleCertGenerate(force bool) {
	dataDir := greyproxyDataHome()
	certFile := filepath.Join(dataDir, "ca-cert.pem")
	keyFile := filepath.Join(dataDir, "ca-key.pem")

	if !force {
		if _, err := os.Stat(certFile); err == nil {
			fmt.Fprintf(os.Stderr, "CA certificate already exists: %s\nUse -f to overwrite.\n", certFile)
			os.Exit(1)
		}
		if _, err := os.Stat(keyFile); err == nil {
			fmt.Fprintf(os.Stderr, "CA key already exists: %s\nUse -f to overwrite.\n", keyFile)
			os.Exit(1)
		}
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate private key: %v\n", err)
		os.Exit(1)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate serial number: %v\n", err)
		os.Exit(1)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "Greyproxy CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create certificate: %v\n", err)
		os.Exit(1)
	}

	if err := os.MkdirAll(dataDir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create data directory: %v\n", err)
		os.Exit(1)
	}

	certOut, err := os.OpenFile(certFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to write certificate: %v\n", err)
		os.Exit(1)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		_ = certOut.Close()
		fmt.Fprintf(os.Stderr, "failed to encode certificate: %v\n", err)
		os.Exit(1)
	}
	_ = certOut.Close()

	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to marshal private key: %v\n", err)
		os.Exit(1)
	}

	keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to write key: %v\n", err)
		os.Exit(1)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		_ = keyOut.Close()
		fmt.Fprintf(os.Stderr, "failed to encode key: %v\n", err)
		os.Exit(1)
	}
	_ = keyOut.Close()

	fmt.Printf("CA certificate: %s\n", certFile)
	fmt.Printf("CA private key: %s\n", keyFile)
	fmt.Println("\nRun 'greyproxy cert install' to trust this CA on your system.")
}

// linuxCertInstallInfo returns the destination path and update command
// appropriate for the current Linux distribution.
func linuxCertInstallInfo() (destPath, updateCmd string) {
	// Arch Linux, Fedora, RHEL, CentOS, openSUSE use update-ca-trust
	if _, err := exec.LookPath("update-ca-trust"); err == nil {
		return "/etc/ca-certificates/trust-source/anchors/greyproxy-ca.crt", "update-ca-trust"
	}
	// Debian, Ubuntu, and derivatives use update-ca-certificates
	return "/usr/local/share/ca-certificates/greyproxy-ca.crt", "update-ca-certificates"
}

func isCertInstalled() bool {
	switch runtime.GOOS {
	case "darwin":
		err := exec.Command("security", "find-certificate", "-c", "Greyproxy CA").Run()
		return err == nil
	case "linux":
		destPath, _ := linuxCertInstallInfo()
		_, err := os.Stat(destPath)
		return err == nil
	default:
		return false
	}
}

func certInstallLocation() string {
	switch runtime.GOOS {
	case "darwin":
		return "/Library/Keychains/System.keychain"
	case "linux":
		destPath, _ := linuxCertInstallInfo()
		return destPath
	default:
		return "(unknown)"
	}
}

func handleCertInstall(force bool) {
	certFile := filepath.Join(greyproxyDataHome(), "ca-cert.pem")

	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "CA certificate not found: %s\nRun 'greyproxy cert generate' first.\n", certFile)
		os.Exit(1)
	}

	if !force && isCertInstalled() {
		fmt.Fprintf(os.Stderr, "CA certificate is already installed at %s\nUse -f to overwrite.\n", certInstallLocation())
		os.Exit(1)
	}

	switch runtime.GOOS {
	case "darwin":
		// Remove any existing Greyproxy CA cert to avoid errSecDuplicateItem (-25294)
		_ = exec.Command("security", "delete-certificate", "-c", "Greyproxy CA").Run()

		fmt.Println("Installing CA certificate into system trust store (requires sudo)...")
		cmd := exec.Command("sudo", "security", "add-trusted-cert",
			"-d", "-p", "ssl", "-p", "basic",
			"-k", "/Library/Keychains/System.keychain",
			certFile,
		)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "\nAutomatic install failed. Please run manually:\n\n")
			fmt.Fprintf(os.Stderr, "  sudo security add-trusted-cert -d -p ssl -p basic -k /Library/Keychains/System.keychain \"%s\"\n\n", certFile)
			os.Exit(1)
		}
		fmt.Printf("CA certificate installed and trusted in %s\n", certInstallLocation())

	case "linux":
		destPath, updateCmd := linuxCertInstallInfo()
		fmt.Println("Installing CA certificate into system trust store (requires sudo)...")
		cpCmd := exec.Command("sudo", "cp", certFile, destPath)
		cpCmd.Stdout = os.Stdout
		cpCmd.Stderr = os.Stderr
		cpCmd.Stdin = os.Stdin
		if err := cpCmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "\nAutomatic install failed. Please run manually:\n\n")
			fmt.Fprintf(os.Stderr, "  sudo cp %s %s\n", certFile, destPath)
			fmt.Fprintf(os.Stderr, "  sudo %s\n\n", updateCmd)
			os.Exit(1)
		}
		updCmd := exec.Command("sudo", updateCmd)
		updCmd.Stdout = os.Stdout
		updCmd.Stderr = os.Stderr
		updCmd.Stdin = os.Stdin
		if err := updCmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "\nCertificate copied but trust update failed. Please run manually:\n\n")
			fmt.Fprintf(os.Stderr, "  sudo %s\n\n", updateCmd)
			os.Exit(1)
		}
		fmt.Printf("CA certificate installed and trusted at %s\n", destPath)

	default:
		fmt.Printf("CA certificate is at: %s\n", certFile)
		fmt.Printf("Please install it manually in your OS trust store.\n")
	}
}

func handleCertUninstall() {
	switch runtime.GOOS {
	case "darwin":
		if !isCertInstalled() {
			fmt.Println("CA certificate is not installed in the system trust store.")
			return
		}
		fmt.Println("Removing CA certificate from system trust store...")
		cmd := exec.Command("security", "delete-certificate", "-c", "Greyproxy CA")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "\nAutomatic removal failed. Please run manually:\n\n")
			fmt.Fprintf(os.Stderr, "  security delete-certificate -c \"Greyproxy CA\"\n\n")
			os.Exit(1)
		}
		fmt.Println("CA certificate removed from system trust store.")

	case "linux":
		destPath, updateCmd := linuxCertInstallInfo()
		if _, err := os.Stat(destPath); os.IsNotExist(err) {
			fmt.Println("CA certificate is not installed in the system trust store.")
			return
		}
		fmt.Println("Removing CA certificate from system trust store (requires sudo)...")
		rmCmd := exec.Command("sudo", "rm", destPath)
		rmCmd.Stdout = os.Stdout
		rmCmd.Stderr = os.Stderr
		rmCmd.Stdin = os.Stdin
		if err := rmCmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "\nAutomatic removal failed. Please run manually:\n\n")
			fmt.Fprintf(os.Stderr, "  sudo rm %s\n", destPath)
			fmt.Fprintf(os.Stderr, "  sudo %s\n\n", updateCmd)
			os.Exit(1)
		}
		updCmd := exec.Command("sudo", updateCmd)
		updCmd.Stdout = os.Stdout
		updCmd.Stderr = os.Stderr
		updCmd.Stdin = os.Stdin
		if err := updCmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "\nCertificate removed but trust update failed. Please run manually:\n\n")
			fmt.Fprintf(os.Stderr, "  sudo %s\n\n", updateCmd)
			os.Exit(1)
		}
		fmt.Printf("CA certificate removed from %s\n", destPath)

	default:
		fmt.Println("Please remove the Greyproxy CA certificate manually from your OS trust store.")
	}
}

// handleCertReload sends a reload request to the running greyproxy instance.
func handleCertReload() {
	apiURL := "http://localhost:43080/api/cert/reload"
	resp, err := http.Post(apiURL, "application/json", bytes.NewReader(nil)) //nolint:gosec,noctx // localhost only, no user input
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to reach greyproxy at %s: %v\n", apiURL, err)
		fmt.Fprintf(os.Stderr, "Is greyproxy running? Check with: greyproxy service status\n")
		os.Exit(1)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "reload failed (HTTP %d): %s\n", resp.StatusCode, string(body))
		os.Exit(1)
	}

	var result struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &result); err == nil && result.Message != "" {
		fmt.Println(result.Message)
	} else {
		fmt.Println("MITM cert reloaded successfully.")
	}
}
