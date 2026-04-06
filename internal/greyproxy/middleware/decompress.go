package middleware

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"io"
	"strings"

	"github.com/klauspost/compress/zstd"
)

// DecompressBody decompresses the response body based on the Content-Encoding header.
// Returns the decompressed bytes and true if decompression was performed,
// or the original bytes and false if no decompression was needed.
func DecompressBody(body []byte, contentEncoding string) ([]byte, bool) {
	if len(body) == 0 || contentEncoding == "" {
		return body, false
	}

	encoding := strings.ToLower(strings.TrimSpace(contentEncoding))
	// Handle multiple encodings (e.g., "gzip, identity") — use the first one
	if i := strings.IndexByte(encoding, ','); i >= 0 {
		encoding = strings.TrimSpace(encoding[:i])
	}

	var reader io.ReadCloser
	var err error

	switch encoding {
	case "gzip":
		reader, err = gzip.NewReader(bytes.NewReader(body))
	case "deflate":
		reader = flate.NewReader(bytes.NewReader(body))
	case "zstd":
		var dec *zstd.Decoder
		dec, err = zstd.NewReader(bytes.NewReader(body))
		if err == nil {
			defer dec.Close()
			decoded, decErr := io.ReadAll(dec)
			if decErr != nil {
				return body, false
			}
			return decoded, true
		}
	default:
		return body, false
	}

	if err != nil {
		return body, false
	}
	defer reader.Close()

	decoded, err := io.ReadAll(reader)
	if err != nil {
		return body, false
	}
	return decoded, true
}
