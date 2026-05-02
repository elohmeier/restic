//go:build darwin && cgo

package backend

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

static CFTypeRef restic_kSecClassIdentity(void) { return kSecClassIdentity; }
static CFTypeRef restic_kSecClass(void) { return kSecClass; }
static CFTypeRef restic_kSecMatchLimit(void) { return kSecMatchLimit; }
static CFTypeRef restic_kSecMatchLimitAll(void) { return kSecMatchLimitAll; }
static CFTypeRef restic_kSecReturnRef(void) { return kSecReturnRef; }

static SecKeyAlgorithm restic_rsa_pkcs1_sha1(void) { return kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1; }
static SecKeyAlgorithm restic_rsa_pkcs1_sha256(void) { return kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256; }
static SecKeyAlgorithm restic_rsa_pkcs1_sha384(void) { return kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384; }
static SecKeyAlgorithm restic_rsa_pkcs1_sha512(void) { return kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512; }
static SecKeyAlgorithm restic_rsa_pss_sha256(void) { return kSecKeyAlgorithmRSASignatureDigestPSSSHA256; }
static SecKeyAlgorithm restic_rsa_pss_sha384(void) { return kSecKeyAlgorithmRSASignatureDigestPSSSHA384; }
static SecKeyAlgorithm restic_rsa_pss_sha512(void) { return kSecKeyAlgorithmRSASignatureDigestPSSSHA512; }
static SecKeyAlgorithm restic_ecdsa_sha1(void) { return kSecKeyAlgorithmECDSASignatureDigestX962SHA1; }
static SecKeyAlgorithm restic_ecdsa_sha256(void) { return kSecKeyAlgorithmECDSASignatureDigestX962SHA256; }
static SecKeyAlgorithm restic_ecdsa_sha384(void) { return kSecKeyAlgorithmECDSASignatureDigestX962SHA384; }
static SecKeyAlgorithm restic_ecdsa_sha512(void) { return kSecKeyAlgorithmECDSASignatureDigestX962SHA512; }

static Boolean restic_sec_key_algorithm_supported(SecKeyRef key, SecKeyOperationType operation, SecKeyAlgorithm algorithm) {
	return SecKeyIsAlgorithmSupported(key, operation, algorithm);
}
*/
import "C"

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"io"
	"strings"
	"unsafe"

	"github.com/restic/restic/internal/errors"
)

type keychainSigner struct {
	key C.SecKeyRef
	pub crypto.PublicKey
}

func (s *keychainSigner) Public() crypto.PublicKey {
	return s.pub
}

func (s *keychainSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	algorithm, err := keychainSignatureAlgorithm(s.key, s.pub, opts)
	if err != nil {
		return nil, err
	}

	data := C.CFDataCreate(C.kCFAllocatorDefault, (*C.UInt8)(unsafe.Pointer(&digest[0])), C.CFIndex(len(digest)))
	if data == 0 {
		return nil, errors.New("unable to allocate digest for Keychain signing")
	}
	defer C.CFRelease(C.CFTypeRef(data))

	var cferr C.CFErrorRef
	sig := C.SecKeyCreateSignature(s.key, algorithm, data, &cferr)
	if sig == 0 {
		return nil, cfError(cferr, "Keychain signing failed")
	}
	defer C.CFRelease(C.CFTypeRef(sig))

	length := C.CFDataGetLength(sig)
	buf := make([]byte, int(length))
	C.CFDataGetBytes(sig, C.CFRange{location: 0, length: length}, (*C.UInt8)(unsafe.Pointer(&buf[0])))
	return buf, nil
}

func keychainSignatureAlgorithm(key C.SecKeyRef, pub crypto.PublicKey, opts crypto.SignerOpts) (C.SecKeyAlgorithm, error) {
	hash := opts.HashFunc()

	var algorithm C.SecKeyAlgorithm
	switch pub.(type) {
	case *rsa.PublicKey:
		if _, ok := opts.(*rsa.PSSOptions); ok {
			switch hash {
			case crypto.SHA256:
				algorithm = C.restic_rsa_pss_sha256()
			case crypto.SHA384:
				algorithm = C.restic_rsa_pss_sha384()
			case crypto.SHA512:
				algorithm = C.restic_rsa_pss_sha512()
			default:
				return 0, errors.Errorf("unsupported RSA-PSS hash %v for Keychain TLS client certificate", hash)
			}
		} else {
			switch hash {
			case crypto.SHA1:
				algorithm = C.restic_rsa_pkcs1_sha1()
			case crypto.SHA256:
				algorithm = C.restic_rsa_pkcs1_sha256()
			case crypto.SHA384:
				algorithm = C.restic_rsa_pkcs1_sha384()
			case crypto.SHA512:
				algorithm = C.restic_rsa_pkcs1_sha512()
			default:
				return 0, errors.Errorf("unsupported RSA hash %v for Keychain TLS client certificate", hash)
			}
		}
	default:
		switch hash {
		case crypto.SHA1:
			algorithm = C.restic_ecdsa_sha1()
		case crypto.SHA256:
			algorithm = C.restic_ecdsa_sha256()
		case crypto.SHA384:
			algorithm = C.restic_ecdsa_sha384()
		case crypto.SHA512:
			algorithm = C.restic_ecdsa_sha512()
		default:
			return 0, errors.Errorf("unsupported ECDSA hash %v for Keychain TLS client certificate", hash)
		}
	}

	if C.restic_sec_key_algorithm_supported(key, C.kSecKeyOperationTypeSign, algorithm) == 0 {
		return 0, errors.Errorf("Keychain identity does not support TLS signature algorithm")
	}
	return algorithm, nil
}

func loadKeychainClientCertificate(selector string) (tls.Certificate, error) {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return tls.Certificate{}, errors.New("empty Keychain identity selector")
	}

	identities, err := copyKeychainIdentities()
	if err != nil {
		return tls.Certificate{}, err
	}
	if identities != 0 {
		defer C.CFRelease(C.CFTypeRef(identities))
	}

	count := C.CFArrayGetCount(identities)
	for i := C.CFIndex(0); i < count; i++ {
		identity := C.SecIdentityRef(C.CFArrayGetValueAtIndex(identities, i))
		cert, err := copyIdentityCertificate(identity)
		if err != nil {
			return tls.Certificate{}, err
		}

		der, err := copyCertificateDER(cert)
		C.CFRelease(C.CFTypeRef(cert))
		if err != nil {
			return tls.Certificate{}, err
		}

		leaf, err := x509.ParseCertificate(der)
		if err != nil {
			return tls.Certificate{}, errors.Errorf("parse Keychain certificate: %v", err)
		}
		if !matchesKeychainSelector(selector, leaf, der) {
			continue
		}

		key, err := copyIdentityPrivateKey(identity)
		if err != nil {
			return tls.Certificate{}, err
		}

		return tls.Certificate{
			Certificate: [][]byte{der},
			PrivateKey:  &keychainSigner{key: key, pub: leaf.PublicKey},
			Leaf:        leaf,
		}, nil
	}

	return tls.Certificate{}, errors.Errorf("no Keychain identity matching %q found", selector)
}

func copyKeychainIdentities() (C.CFArrayRef, error) {
	query := C.CFDictionaryCreateMutable(C.kCFAllocatorDefault, 0, &C.kCFTypeDictionaryKeyCallBacks, &C.kCFTypeDictionaryValueCallBacks)
	if query == 0 {
		return 0, errors.New("unable to allocate Keychain query")
	}
	defer C.CFRelease(C.CFTypeRef(query))

	C.CFDictionarySetValue(query, unsafe.Pointer(C.restic_kSecClass()), unsafe.Pointer(C.restic_kSecClassIdentity()))
	C.CFDictionarySetValue(query, unsafe.Pointer(C.restic_kSecMatchLimit()), unsafe.Pointer(C.restic_kSecMatchLimitAll()))
	C.CFDictionarySetValue(query, unsafe.Pointer(C.restic_kSecReturnRef()), unsafe.Pointer(C.kCFBooleanTrue))

	var result C.CFTypeRef
	status := C.SecItemCopyMatching(C.CFDictionaryRef(query), &result)
	if status != C.errSecSuccess {
		return 0, osStatusError(status, "search Keychain identities")
	}
	return C.CFArrayRef(result), nil
}

func copyIdentityCertificate(identity C.SecIdentityRef) (C.SecCertificateRef, error) {
	var cert C.SecCertificateRef
	status := C.SecIdentityCopyCertificate(identity, &cert)
	if status != C.errSecSuccess {
		return 0, osStatusError(status, "copy Keychain identity certificate")
	}
	return cert, nil
}

func copyIdentityPrivateKey(identity C.SecIdentityRef) (C.SecKeyRef, error) {
	var key C.SecKeyRef
	status := C.SecIdentityCopyPrivateKey(identity, &key)
	if status != C.errSecSuccess {
		return 0, osStatusError(status, "copy Keychain identity private key")
	}
	return key, nil
}

func copyCertificateDER(cert C.SecCertificateRef) ([]byte, error) {
	data := C.SecCertificateCopyData(cert)
	if data == 0 {
		return nil, errors.New("copy Keychain certificate data")
	}
	defer C.CFRelease(C.CFTypeRef(data))

	length := C.CFDataGetLength(data)
	buf := make([]byte, int(length))
	C.CFDataGetBytes(data, C.CFRange{location: 0, length: length}, (*C.UInt8)(unsafe.Pointer(&buf[0])))
	return buf, nil
}

func matchesKeychainSelector(selector string, cert *x509.Certificate, der []byte) bool {
	if strings.EqualFold(selector, cert.Subject.CommonName) {
		return true
	}

	sum := sha256.Sum256(der)
	fingerprint := hex.EncodeToString(sum[:])
	normalizedSelector := strings.ToLower(strings.ReplaceAll(selector, ":", ""))
	return normalizedSelector == fingerprint
}

func osStatusError(status C.OSStatus, context string) error {
	return errors.Errorf("%s: macOS Security framework status %d", context, int32(status))
}

func cfError(cferr C.CFErrorRef, fallback string) error {
	if cferr == 0 {
		return errors.New(fallback)
	}
	defer C.CFRelease(C.CFTypeRef(cferr))
	return errors.Errorf("%s: macOS Security framework error %d", fallback, int64(C.CFErrorGetCode(cferr)))
}
