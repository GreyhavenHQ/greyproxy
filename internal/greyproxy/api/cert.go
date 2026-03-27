package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/gin-gonic/gin"
)

type certStatusResponse struct {
	Generated       bool              `json:"generated"`
	CertPath        string            `json:"certPath"`
	KeyPath         string            `json:"keyPath"`
	Subject         string            `json:"subject,omitempty"`
	ExpiresAt       *time.Time        `json:"expiresAt,omitempty"`
	Installed       bool              `json:"installed"`
	InstallCommands map[string]string `json:"installCommands"`
}

func buildCertStatus(dataHome string) certStatusResponse {
	certPath := filepath.Join(dataHome, "ca-cert.pem")
	keyPath := filepath.Join(dataHome, "ca-key.pem")

	resp := certStatusResponse{
		CertPath:        certPath,
		KeyPath:         keyPath,
		InstallCommands: buildInstallCommands(certPath),
	}

	// Check if cert exists and parse it
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return resp
	}
	if _, err := os.Stat(keyPath); err != nil {
		return resp
	}

	resp.Generated = true

	block, _ := pem.Decode(certData)
	if block == nil {
		return resp
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return resp
	}

	resp.Subject = cert.Subject.CommonName
	resp.ExpiresAt = &cert.NotAfter
	resp.Installed = isCertInstalled(certPath)

	return resp
}

func buildInstallCommands(certPath string) map[string]string {
	cmds := make(map[string]string)
	switch runtime.GOOS {
	case "darwin":
		cmds["macos"] = fmt.Sprintf("sudo security add-trusted-cert -d -p ssl -p basic -k /Library/Keychains/System.keychain \"%s\"", certPath)
	case "linux":
		destPath, updateCmd := linuxCertInstallInfo()
		cmds["linux"] = fmt.Sprintf("sudo cp \"%s\" %s && sudo %s", certPath, destPath, updateCmd)
	}
	return cmds
}

// linuxCertInstallInfo returns the destination path and update command
// appropriate for the current Linux distribution.
func linuxCertInstallInfo() (destPath, updateCmd string) {
	if _, err := exec.LookPath("update-ca-trust"); err == nil {
		return "/etc/ca-certificates/trust-source/anchors/greyproxy-ca.crt", "update-ca-trust"
	}
	return "/usr/local/share/ca-certificates/greyproxy-ca.crt", "update-ca-certificates"
}

func isCertInstalled(certPath string) bool {
	switch runtime.GOOS {
	case "darwin":
		// Check if Greyproxy CA is in the system keychain
		out, err := exec.Command("security", "find-certificate", "-c", "Greyproxy CA", "/Library/Keychains/System.keychain").Output()
		return err == nil && len(out) > 0
	case "linux":
		destPath, _ := linuxCertInstallInfo()
		_, err := os.Stat(destPath)
		return err == nil
	}
	return false
}

func CertStatusHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, buildCertStatus(s.DataHome))
	}
}

func CertGenerateHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		force := c.Query("force") == "true"
		dataHome := s.DataHome

		certFile := filepath.Join(dataHome, "ca-cert.pem")
		keyFile := filepath.Join(dataHome, "ca-key.pem")

		if !force {
			if _, err := os.Stat(certFile); err == nil {
				c.JSON(http.StatusConflict, gin.H{
					"error": "CA certificate already exists. Use ?force=true to overwrite.",
				})
				return
			}
		}

		if err := os.MkdirAll(dataHome, 0700); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to create data directory: %v", err)})
			return
		}

		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to generate key: %v", err)})
			return
		}

		serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to generate serial: %v", err)})
			return
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
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to create certificate: %v", err)})
			return
		}

		certOut, err := os.OpenFile(certFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to write cert: %v", err)})
			return
		}
		if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
			certOut.Close()
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to encode cert: %v", err)})
			return
		}
		certOut.Close()

		keyBytes, err := x509.MarshalECPrivateKey(privateKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to marshal key: %v", err)})
			return
		}

		keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to write key: %v", err)})
			return
		}
		if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
			keyOut.Close()
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to encode key: %v", err)})
			return
		}
		keyOut.Close()

		c.JSON(http.StatusOK, gin.H{
			"message":    "Certificate generated and reloaded.",
			"certStatus": buildCertStatus(dataHome),
		})
	}
}

func CertDownloadHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		certPath := filepath.Join(s.DataHome, "ca-cert.pem")
		if _, err := os.Stat(certPath); err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "CA certificate not found. Generate one first."})
			return
		}
		c.Header("Content-Disposition", "attachment; filename=greyproxy-ca.pem")
		c.File(certPath)
	}
}

// CertReloadHandler triggers a live reload of the MITM CA certificate.
// It is a no-op if the cert file has not changed since the last reload.
func CertReloadHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.ReloadCertFn == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "cert reload not available"})
			return
		}

		// Skip reload if the cert file has not changed since last load.
		if s.CertMtimeFn != nil {
			certFile := filepath.Join(s.DataHome, "ca-cert.pem")
			if info, err := os.Stat(certFile); err == nil {
				if !info.ModTime().After(s.CertMtimeFn()) {
					c.JSON(http.StatusOK, gin.H{
						"message":    "cert unchanged, no reload needed",
						"certStatus": buildCertStatus(s.DataHome),
					})
					return
				}
			}
		}

		if err := s.ReloadCertFn(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("reload failed: %v", err)})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"message":    "MITM cert reloaded",
			"certStatus": buildCertStatus(s.DataHome),
		})
	}
}
