package crypto

import (
	"encoding"
	"io"
)

type (
	// PublicKey is a generic public key interface used by dbft.
	PublicKey interface {
		encoding.BinaryMarshaler
		encoding.BinaryUnmarshaler

		// Verify verifies if sig is indeed msg's signature.
		Verify(msg, sig []byte) error
	}

	// PrivateKey is a generic private key interface used by dbft.
	PrivateKey interface {
		encoding.BinaryMarshaler
		encoding.BinaryUnmarshaler

		// Sign returns msg's signature and error on failure.
		Sign(msg []byte) (sig []byte, err error)
	}
)

type suiteType byte

const (
	// SuiteECDSA is a ECDSA suite over P-256 curve
	// with 64-byte uncompressed signatures.
	SuiteECDSA suiteType = 1 + iota
	SuiteBLS
)

const defaultSuite = SuiteECDSA

// Generate generates new key pair using r
// as a source of entropy.
func Generate(r io.Reader) (PrivateKey, PublicKey) {
	return GenerateWith(defaultSuite, r)
}

// GenerateWith generates new key pair for suite t
// using r as a source of entropy.
func GenerateWith(t suiteType, r io.Reader) (PrivateKey, PublicKey) {
	switch t {
	case SuiteECDSA:
		return generateECDSA(r)
	case SuiteBLS:
		return generateBLS(r)
	}

	return nil, nil
}
