//go:build !darwin || !cgo

package backend

import (
	"crypto/tls"

	"github.com/restic/restic/internal/errors"
)

func loadKeychainClientCertificate(selector string) (tls.Certificate, error) {
	return tls.Certificate{}, errors.Errorf("TLS client certificate Keychain identity %q is only supported on macOS builds with cgo enabled", selector)
}
