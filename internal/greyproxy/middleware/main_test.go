package middleware

import (
	"os"
	"testing"

	"github.com/greyhavenhq/greyproxy/internal/gostcore/logger"
)

// Tests in this package touch code paths that call logger.Default().Warnf.
// In production the binary installs a real logger via logger.SetDefault;
// under `go test` nothing does. Install a no-op logger so the Warnf calls
// in drainPending/cascade fallback paths don't panic on nil.
func TestMain(m *testing.M) {
	logger.SetDefault(nopLogger{})
	os.Exit(m.Run())
}

type nopLogger struct{}

func (nopLogger) WithFields(map[string]any) logger.Logger { return nopLogger{} }
func (nopLogger) Trace(...any)                            {}
func (nopLogger) Tracef(string, ...any)                   {}
func (nopLogger) Debug(...any)                            {}
func (nopLogger) Debugf(string, ...any)                   {}
func (nopLogger) Info(...any)                             {}
func (nopLogger) Infof(string, ...any)                    {}
func (nopLogger) Warn(...any)                             {}
func (nopLogger) Warnf(string, ...any)                    {}
func (nopLogger) Error(...any)                            {}
func (nopLogger) Errorf(string, ...any)                   {}
func (nopLogger) Fatal(...any)                            {}
func (nopLogger) Fatalf(string, ...any)                   {}
func (nopLogger) GetLevel() logger.LogLevel               { return logger.InfoLevel }
func (nopLogger) IsLevelEnabled(logger.LogLevel) bool     { return false }
